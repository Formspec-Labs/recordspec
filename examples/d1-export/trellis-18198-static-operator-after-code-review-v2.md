# Trellis 18198 operator preparation — bounded static AFTER review

Review ID: TRELLIS-18198-OPERATOR-AFTER-V2-2026-10-09. Independent nonauthor `/root/oidc_code_review`. Full semi-formal-code-review method applied incrementally from the preceding full BEFORE review, `/Users/mikewolfd/.agents/skills/semi-formal-code-review/SKILL.md`. Only this certificate written. No scripts invoked, network/provider/DB actions, Cargo or native commands. Python AST parsing and file hashing are read-only review operations.

## Findings and patch summary

**APPROVE exact V3 packet for static operator preparation. All three previous blockers resolved.** This approval establishes reviewed source readiness for a later expressly authorized operation; it supplies no launch, positive caller admission or export evidence. Existing deny-all grants deliberately prevent positive case access.

F1 — RESOLVED / correctness / launcher:29–35. Private database JSON now has a fixed digest checked before parsing, exact selected signing-key path and bytes are checked, and the parsed PostgreSQL URL must match loopback18185, selected database and username. Bind remains fixed18198. All corresponding current input digests independently match the packet. This closes the unpinned database/key input gap.

F2 — RESOLVED / correctness / launcher:12–13,22–35 and readback:8–9,15–17,29. Each prior assert guard is now require(condition,message) with unconditional SystemExit on failure. Both files parse successfully and contain zero Assert AST nodes. Optimization cannot remove these guards.

F3 — RESOLVED / security / readback:20. Explicit ProxyHandler({}) replaces the default proxy handler; RefuseRedirects remains. The installed urllib build_opener implementation inspected during BEFORE removes default handlers overridden by passed instances, so environment proxies no longer broaden the destination. The fixed loopback URL and redirect refusal remain intact.

F4 — OBSERVATION / test coverage. No script execution tests added or run. Static reasoning covers the corrections; AST success does not prove live CLI/network behavior. Coverage remains limited accordingly, without blocking this expressly static preparation gate.

The only reviewed changed files are the two operator Python scripts and successor public packet; profile/grants/private database/key/binary were independently rehashed as inputs. Original BEFORE certificate is preserved. Persistent artifact-backend selection is a separately requested follow-up and is not silently added by this approval.

## Function trace

All Python locations below refer to files in the private directory named by the packet.

| Function / caller | File:line | Inputs → outputs | Verified behavior |
|---|---|---|---|
| require | start-trellis-reviewed-v4.py:12 | condition/message → return or SystemExit | Explicit refusal survives optimized Python. |
| digest/main | launcher:11,14–35 | Binary/profile/grant/DB/key bytes and CLI → verified selections | Pins checked before exec; DB/key values checked before environment construction. |
| execve branch | launcher:37–48 | Narrow environment → retained binary | Dry-run default returns before exec; only --execute reaches it. Absolute binary plus PATH and five explicit Trellis variables; inherited auth/storage/artifact overrides omitted. |
| require/main | readback-trellis-reviewed-v4.py:8–20 | Scope/stdin token/profile → validated request inputs and opener | Nonempty single path segment, bounded whitespace-free token, no environment proxy and no redirect following. |
| get | readback:21–32 | scope/bearer → status/body | Exact loopback18198, encoded path, WOS tuple headers, ten-second timeout, bounded successful body; HTTPError becomes failure status with empty body. |
| result branch | readback:33–46 | Four responses → public diagnostic and optional raw030 | Success requires401/401/403/200 and expected registry digest. No token persisted. Existing output directory refuses creation. |
| maintained server startup | trellis-server/src/state.rs:419–475 | Explicit environment → state | Previously inspected: strict OIDC before signing key and PostgreSQL pool/migrations. Absent artifact overrides retain default in-memory artifacts. |

The `if __name__ == "__main__"` guards are the immediate callers; no other callers are provided in the bounded packet. Existing maintained client endpoint matches readback, but the secondary Python path cannot substitute for WOS's Common OidcClientCredentials→TrellisServiceClient qualification.

## Data flow and invariants

The private database digest and selected key constants originate in frozen source, are compared before use, and validated DB/key values escape only into the child environment. Current grants digest is an explicit required operator argument; a future grant change requires new exact review/freeze. Profile and binary are fixed by digest. Secret values are neither printed nor copied into the certificate. Hash-before-open/exec does not claim immunity from concurrent trusted-operator file replacement; freeze and private-directory custody remain operation prerequisites.

Readback's bearer originates on stdin and is used only in the selected and negative-scope Authorization headers; diagnostic output contains status/digest only. Explicit empty proxy configuration and disabled redirects preserve the intended destination. Profile tuple creates headers, not grant authority. Empty current grants still refuse all cases, and existing fresh-case/exporter identity requirements remain pending. No case456 reuse or implicit administer elevation appears.

## Tests, edge cases and exploration updates

Reviewer executed no tests or scripts. Both files pass AST parsing; zero Assert nodes confirms the specific optimization bypass removal. Wrong input digest, wrong key path, wrong DB tuple or bind takes require→SystemExit before exec. Empty grants without explicit deny-all selection refuse. Dry-run reaches only diagnostic print and return. Inherited proxies cannot install a proxy handler because the explicit empty handler overrides it. Redirects refuse. Selected403 produces failed readback; no positive current-provider proof is inferred. These are source-derived expectations, not measured results.

H1 every child-affecting local selection is frozen: previous finding resolved for DB/key/profile/grants/binary by explicit pins and validations; dynamic current-grant replacement remains deliberate operator-controlled authority. H2 asserts can disappear: resolved, no Assert nodes remain. H3 proxy inheritance redirects bearer: resolved by explicit empty proxy handler. H4 preparation proves live readiness: rejected; live operation remains outside review. No further static blocker found in the bounded corrections.

## Exact pins

| Input | SHA-256 |
|---|---|
| `trellis-18198-static-operator-before-code-review-v1.md` | `9394cd35cb8f99d13523f7303d91e8bf8e7e3cf7261b1e43537f290fea2a71ff` |
| `trellis-18198-static-operator-preparation-v3.json` | `999654db2a9c7fe81ef7300ca5243631acfba873b0f65a1df432327ea8550108` |
| `start-trellis-reviewed-v4.py` | `7ff5649223ccf0c9b98a885f3c34156c294e0ea1dc3115791ab6c258fd624a23` |
| `readback-trellis-reviewed-v4.py` | `11e54cf65d79ee11d9dcb13bcc4baf4ff6328043c692d796923fc2931f638bf0` |
| profile | `c8de0c4bfba003b93c2ef28a937a3e8bef1f21c3d12f26685af7a294c196e057` |
| grants | `2ee9697269d53fdb94daf48af6d6a586a92b81bbdaf0dd24e95b38c6ce0caae0` |
| private database config | `d15d5c863b4920cfc4b91c6ac72fbd08dbd7cb7cc81362531cf324928f01a983` |
| selected retained key file | `62644accd6ef7af276945418ee794ce6428ac63a0a79f78180addd372b053608` |
| qualified binary | `f0a0eb62da9d52c5a5e5a2bac8f60af8b7ff97084cd0de6c5cae63d5256e90c7` |

All above current input hashes match. Public packet SHA matches the supplied999654db… pin. Private secret contents remain undisclosed.

## Conclusion

VERDICT: APPROVE exact V3 static operator preparation and bounded source corrections.

The corrections meet the stated static intent. Coverage of corrected guards: ADEQUATE for source analysis; INSUFFICIENT for operational behavior, with no script tests/execution claimed. Confidence: HIGH for inspected changes, pins and refusal traces. Launch, DB migrations, maintained-provider positive exact-case200, durable artifact selection, agency trust and actual D1 export remain separate pending gates. This certificate authorizes no live action.
