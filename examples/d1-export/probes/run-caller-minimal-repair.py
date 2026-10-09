"""Run only during the granted native window; retain minimal lock repair evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import tomllib

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "examples/d1-export/probes/member-input-after"
EXPECTED_START = "34de175327773ca900c0fb4552ef0adfc0105f3fb336fd9e54d53adda7c00b1b"
LIMIT_SECONDS = 900

def digest(data):
    return hashlib.sha256(data).hexdigest()

def package_versions(data):
    result = {}
    for package in tomllib.loads(data.decode())["package"]:
        key = (package["name"], package.get("source", "local"))
        result.setdefault(key, set()).add(package["version"])
    return result

def lock_diff(before, after):
    old, new = package_versions(before), package_versions(after)
    removed, added, replacements = [], [], []
    for key in sorted(old.keys() | new.keys()):
        gone = sorted(old.get(key, set()) - new.get(key, set()))
        fresh = sorted(new.get(key, set()) - old.get(key, set()))
        removed.extend({"name": key[0], "source": key[1], "version": v} for v in gone)
        added.extend({"name": key[0], "source": key[1], "version": v} for v in fresh)
        if key[1] != "local" and gone and fresh:
            replacements.append({"name": key[0], "source": key[1], "removed": gone, "added": fresh})
    return {"removed": removed, "added": added, "registryVersionReplacements": replacements}

lock = ROOT / "Cargo.lock"
starting = lock.read_bytes()
if digest(starting) != EXPECTED_START:
    raise SystemExit("Starting lock differs from the authorized restored bytes; no Cargo started.")
label, attempt = "server-check-minimal", 1
while (OUT / (label + "-receipt.json")).exists():
    attempt += 1
    label = f"server-check-minimal-attempt-{attempt}"
paths, seen = [Path(__file__).resolve()], set()

def local_inputs(manifest):
    manifest = manifest.resolve()
    if manifest in seen:
        return
    seen.add(manifest)
    paths.append(manifest)
    paths.extend(manifest.parent.rglob("*.rs"))
    data = tomllib.loads(manifest.read_text())
    workspace = next((parent / "Cargo.toml" for parent in manifest.parents
                      if (parent / "Cargo.toml").is_file()
                      and "workspace" in tomllib.loads((parent / "Cargo.toml").read_text())), None)
    workspace_deps = {}
    if workspace:
        paths.append(workspace)
        workspace_deps = tomllib.loads(workspace.read_text()).get("workspace", {}).get("dependencies", {})
    for table in [data, *data.get("target", {}).values()]:
        for section in ["dependencies", "dev-dependencies", "build-dependencies"]:
            for key, dependency in table.get(section, {}).items():
                if not isinstance(dependency, dict):
                    continue
                base = manifest.parent
                if dependency.get("workspace"):
                    dependency = workspace_deps.get(key, {})
                    base = workspace.parent
                if isinstance(dependency, dict) and "path" in dependency:
                    local_inputs(base / dependency["path"] / "Cargo.toml")

local_inputs(ROOT / "crates/trellis-server/Cargo.toml")
local_inputs(ROOT / "crates/trellis-export-writer/Cargo.toml")
# Literal includes can consume schema/profile/fixture bytes outside a package.
for source in list(paths):
    if source.suffix == ".rs":
        for relative in re.findall(r'include_(?:str|bytes)!\s*\(\s*"([^"]+)"', source.read_text()):
            included = (source.parent / relative).resolve()
            if included.is_file():
                paths.append(included)
# This build script reads an external JSON schema rather than using include!.
paths.append(ROOT.parent / "stack-common/schemas/error.schema.json")
for parent in [*ROOT.parents, ROOT]:
    for name in [".cargo/config", ".cargo/config.toml", "rust-toolchain", "rust-toolchain.toml"]:
        if (parent / name).is_file():
            paths.append(parent / name)
for name in ["config", "config.toml"]:
    if (Path.home() / ".cargo" / name).is_file():
        paths.append(Path.home() / ".cargo" / name)
paths.extend(p for p in (ROOT / "fixtures/vectors").rglob("*") if p.is_file())
guard = {str(p.resolve()): digest(p.read_bytes()) for p in paths if p.is_file()}
argv = [str(Path.home() / ".cargo/bin/cargo"), "check", "--offline", "-j1", "-p", "trellis-server"]
settings = ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_TARGET_DIR", "RUSTUP_TOOLCHAIN", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL",
            "CARGO_PROFILE_DEV_CODEGEN_UNITS", "CARGO_PROFILE_DEV_INCREMENTAL"]
receipt = {"argv": argv, "cwd": str(ROOT), "startedAtUnix": time.time(),
           "startingLockSha256": digest(starting), "sourceAndFixtureSha256": guard,
           "buildEnvironment": {name: os.environ.get(name) for name in settings},
           "rustcVersion": subprocess.check_output([str(Path.home() / ".cargo/bin/rustc"), "--version"], text=True).strip(),
           "budgetSeconds": LIMIT_SECONDS, "progressIntervalSeconds": 30,
           "lockPolicy": "Stop on any registry version replacement or more than ten added registry package/version entries; additions and orphan removals are retained for review.",
           "receiptLabel": label, "progress": []}
(OUT / (label + "-starting.cargo-lock")).write_bytes(starting)
log_path = OUT / (label + ".log")
process, observed_lock = None, starting

def stop_group(sig):
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass

def group_absent():
    try:
        os.killpg(process.pid, 0)
        return False
    except ProcessLookupError:
        return True

def observe_lock():
    global observed_lock
    current = lock.read_bytes()
    if current == observed_lock:
        return
    try:
        difference = lock_diff(starting, current)
    except (tomllib.TOMLDecodeError, KeyError):
        return  # Retry a partial write on the next short poll.
    observed_lock = current
    (OUT / (label + "-resolved.cargo-lock")).write_bytes(current)
    receipt["resolvedLockSha256"] = digest(current)
    receipt["packageVersionDiff"] = difference
    registry_additions = [p for p in difference["added"] if p["source"] != "local"]
    if difference["registryVersionReplacements"] or len(registry_additions) > 10:
        receipt["resolverPolicyStopped"] = True
        stop_group(signal.SIGTERM)

def retain_final_lock():
    current = lock.read_bytes()
    (OUT / (label + "-resolved.cargo-lock")).write_bytes(current)
    receipt["resolvedLockSha256"] = digest(current)
    receipt["packageVersionDiff"] = lock_diff(starting, current)

try:
    with log_path.open("wb") as log:
        process = subprocess.Popen(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        receipt["ownedProcessGroup"] = process.pid
        started, next_progress = time.monotonic(), time.monotonic()
        while process.poll() is None:
            observe_lock()
            now = time.monotonic()
            if now >= next_progress:
                tail = log_path.read_text(errors="replace").splitlines()[-3:]
                progress = {"elapsedSeconds": round(now - started, 1), "logTail": tail}
                receipt["progress"].append(progress)
                print(json.dumps(progress), flush=True)
                next_progress = now + 30
            if now - started >= LIMIT_SECONDS:
                receipt["timedOut"] = True
                stop_group(signal.SIGTERM)
                break
            if receipt.get("resolverPolicyStopped"):
                break
            time.sleep(0.1)
        try:
            receipt["exitCode"] = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            stop_group(signal.SIGKILL)
            receipt["exitCode"] = process.wait(timeout=10)
        observe_lock()
        retain_final_lock()
finally:
    try:
        if process is not None:
            if not group_absent():
                stop_group(signal.SIGTERM)
                deadline = time.monotonic() + 5
                while not group_absent() and time.monotonic() < deadline:
                    time.sleep(0.1)
                if not group_absent():
                    stop_group(signal.SIGKILL)
                    deadline = time.monotonic() + 5
                    while not group_absent() and time.monotonic() < deadline:
                        time.sleep(0.1)
            receipt["ownedGroupAbsent"] = group_absent()
    except Exception as error:
        receipt["cleanupError"] = str(error)
        receipt["ownedGroupAbsent"] = False
    finally:
        try:
            lock.write_bytes(starting)
            receipt["startingLockRestored"] = lock.read_bytes() == starting
        except Exception as error:
            receipt["startingLockRestored"] = False
            receipt["lockRestorationError"] = str(error)
        receipt["finishedAtUnix"] = time.time()
        receipt["sourceAndFixtureDrift"] = {
            p: digest(Path(p).read_bytes()) if Path(p).is_file() else "missing"
            for p, expected in guard.items()
            if not Path(p).is_file() or digest(Path(p).read_bytes()) != expected}
        receipt["logSha256"] = digest(log_path.read_bytes()) if log_path.exists() else None
        (OUT / (label + "-receipt.json")).write_text(json.dumps(receipt, indent=2) + "\n")
print(json.dumps({k: v for k, v in receipt.items() if k != "sourceAndFixtureSha256"}), flush=True)
if not receipt.get("ownedGroupAbsent", True) or not receipt["startingLockRestored"]:
    raise SystemExit(125)
if receipt.get("resolverPolicyStopped"):
    raise SystemExit(126)
raise SystemExit(124 if receipt.get("timedOut") else receipt.get("exitCode", 1))
