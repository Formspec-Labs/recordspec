"""Retain one serialized native command and restore the pre-existing lock."""
import hashlib, json, os, signal, subprocess, sys, time, tomllib
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "examples/d1-export/probes/member-input-after"
OUT.mkdir(exist_ok=True)
def digest(data): return hashlib.sha256(data).hexdigest()
commands = {
 "writer-tests": ["test", "--offline", "--locked", "-j1", "-p", "trellis-export-writer", "--features", "fixture-inputs", "--all-targets"],
 "writer-clippy": ["clippy", "--offline", "--locked", "-j1", "-p", "trellis-export-writer", "--features", "fixture-inputs", "--all-targets", "--", "-D", "warnings"],
 "server-check": ["check", "--offline", "--locked", "-j1", "-p", "trellis-server"],
}
for name, fixture in [("probe-010", "010-certificate-of-completion-inline"), ("probe-006", "006-signature-affirmations-inline"), ("probe-007", "007-intake-handoffs-public-create")]:
 commands[name] = ["run", "--offline", "--locked", "-j1", "-p", "trellis-export-writer", "--features", "fixture-inputs", "--example", "full-member-qualification", "--", str(OUT/name), fixture]
commands["probe-010-missing-inline"] = [*commands["probe-010"][:-2], str(OUT/"probe-010-missing-inline"), "010-certificate-of-completion-inline", "--omit-payloads"]
name = sys.argv[1]
label = name
attempt = 1
while (OUT/(label+"-receipt.json")).exists():
 attempt += 1
 label = f"{name}-attempt-{attempt}"
if name.startswith("probe-"):
 commands[name] = [str(OUT/label) if value==str(OUT/name) else value for value in commands[name]]
argv = [str(Path.home()/".cargo/bin/cargo"), *commands[name]]
lock = ROOT/"Cargo.lock"
starting = lock.read_bytes()
generated = (ROOT/"examples/d1-export/probes/controlled-lock-generated.cargo-lock").read_bytes()
paths = [Path(__file__).resolve()]
seen = set()
def local_inputs(manifest):
 manifest = manifest.resolve()
 if manifest in seen: return
 seen.add(manifest)
 paths.append(manifest)
 paths.extend(manifest.parent.rglob("*.rs"))
 data = tomllib.loads(manifest.read_text())
 workspace = next((parent/"Cargo.toml" for parent in manifest.parents if (parent/"Cargo.toml").is_file() and "workspace" in tomllib.loads((parent/"Cargo.toml").read_text())), None)
 workspace_deps = {}
 if workspace:
  paths.append(workspace)
  workspace_deps = tomllib.loads(workspace.read_text()).get("workspace", {}).get("dependencies", {})
 tables = [data]
 tables.extend(data.get("target", {}).values())
 for table in tables:
  for section in ["dependencies", "dev-dependencies", "build-dependencies"]:
   for key, dependency in table.get(section, {}).items():
    if not isinstance(dependency, dict): continue
    base = manifest.parent
    if dependency.get("workspace"):
     dependency = workspace_deps.get(key, {})
     base = workspace.parent
    if isinstance(dependency, dict) and "path" in dependency:
     local_inputs(base/dependency["path"]/"Cargo.toml")
local_inputs(ROOT/"crates/trellis-export-writer/Cargo.toml")
if name == "server-check": local_inputs(ROOT/"crates/trellis-server/Cargo.toml")
for config in [ROOT/"Cargo.toml", ROOT.parent/".cargo/config.toml", ROOT/"rust-toolchain.toml"]:
 if config.is_file(): paths.append(config)
# All existing writer tests and fixture utility inputs, including issuer keys.
paths.extend(p for p in (ROOT/"fixtures/vectors").rglob("*") if p.is_file())
guard = {str(p.resolve()): digest(p.read_bytes()) for p in paths if p.is_file() and p.resolve()!=lock}
receipt = {"argv": argv, "cwd": str(ROOT), "startedAtUnix": time.time(), "startingLockSha256": digest(starting), "generatedLockSha256": digest(generated), "sourceAndFixtureSha256": guard, "receiptLabel": label, "rustcVersion": subprocess.check_output([str(Path.home()/".cargo/bin/rustc"), "--version"], text=True).strip()}
log_path = OUT/(label+".log")
process = None
try:
 lock.write_bytes(generated)
 with log_path.open("wb") as log:
  process = subprocess.Popen(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
  receipt["ownedProcessGroup"] = process.pid
  try: receipt["exitCode"] = process.wait(timeout=300)
  except subprocess.TimeoutExpired:
   receipt["timedOut"] = True
   os.killpg(process.pid, signal.SIGTERM)
   try: receipt["exitCode"] = process.wait(timeout=10)
   except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGKILL); receipt["exitCode"] = process.wait(timeout=10)
finally:
 try:
  if process is not None:
   def group_absent():
    try: os.killpg(process.pid, 0); return False
    except ProcessLookupError: return True
   def stop_group(sig):
    try: os.killpg(process.pid, sig)
    except ProcessLookupError: pass
   if not group_absent():
    receipt["cleanupRequired"] = True
    stop_group(signal.SIGTERM)
    deadline = time.monotonic()+5
    while not group_absent() and time.monotonic()<deadline: time.sleep(0.1)
    if not group_absent():
     stop_group(signal.SIGKILL)
     deadline = time.monotonic()+5
     while not group_absent() and time.monotonic()<deadline: time.sleep(0.1)
   receipt["ownedGroupAbsent"] = group_absent()
 except Exception as error:
  receipt["cleanupError"] = str(error)
  receipt["ownedGroupAbsent"] = False
 finally:
  try:
   lock.write_bytes(starting)
   receipt["startingLockRestored"] = lock.read_bytes()==starting
  except Exception as error:
   receipt["startingLockRestored"] = False
   receipt["lockRestorationError"] = str(error)
 receipt["finishedAtUnix"] = time.time()
 receipt["sourceAndFixtureDrift"] = {p: digest(Path(p).read_bytes()) for p,h in guard.items() if digest(Path(p).read_bytes())!=h}
 receipt["logSha256"] = digest(log_path.read_bytes()) if log_path.exists() else None
 binary = ROOT.parent/".cargo-target/debug/examples/full-member-qualification"
 if name.startswith("probe-"):
  log_text = log_path.read_text()
  receipt["probeExecutionObserved"] = "Finished " in log_text and "Running `" in log_text
  if receipt["probeExecutionObserved"] and binary.is_file(): receipt["executedBinarySha256"] = digest(binary.read_bytes())
 receipt["outputSha256"] = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in (OUT/label).rglob("*") if p.is_file()}
 (OUT/(label+"-receipt.json")).write_text(json.dumps(receipt, indent=2)+"\n")
print(json.dumps({k:v for k,v in receipt.items() if k!="sourceAndFixtureSha256"}, indent=2))
if not receipt.get("ownedGroupAbsent", True) or not receipt["startingLockRestored"]:
 print("Native window retained: cleanup or lock restoration incomplete.")
 sys.exit(125)
sys.exit(receipt.get("exitCode", 1) if not receipt.get("timedOut") else 124)
