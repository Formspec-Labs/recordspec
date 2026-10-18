# Trellis Specs

This folder contains the normalized Trellis specification set.

## Reading Order

Read the top-level documents first:

1. [`trellis-agreement.md`](trellis-agreement.md) — non-normative decision gate and product invariants.
2. [`trellis-core.md`](trellis-core.md) — normative Phase 1 byte protocol for append, verify, and export.
3. [`trellis-operational-companion.md`](trellis-operational-companion.md) — normative Phase 2+ operator obligations.
4. [`wos-trellis-verification.md`](wos-trellis-verification.md) — WOS-domain validator obligations composed with Trellis Core verification.
5. [`trellis-http-api.schema.json`](trellis-http-api.schema.json) — normative machine-readable schema for the Trellis substrate-service HTTP boundary.
6. [`trellis-requirements-matrix.md`](trellis-requirements-matrix.md) — traceability matrix. Prose in Core, the Operational Companion, WOS-Trellis verification, and the HTTP API schema wins on conflict.

## Normative Authority

`trellis-core.md` and `trellis-operational-companion.md` are the normative prose specifications for Trellis itself. `wos-trellis-verification.md` is normative only for WOS deployments that compose Trellis Core verification with WOS record semantics.

`trellis-http-api.schema.json` is the normative machine-readable contract for the `trellis-service-client` / `trellis-server` HTTP substrate boundary. It defines the product-edge JSON append envelope, append response, event-type registry JSON shape, error body, route set, scope selector (the `x-stack-scope-key` header and the `<scope key>.<ledger id>` ledger scope, ADR 0168), and binary media responses. It does not redefine the proof artifact; export bundle bytes remain governed by Trellis Core.

`trellis-agreement.md` is a sign-off gate for scope and invariants. It does not impose implementor conformance obligations.

`trellis-requirements-matrix.md` exists to preserve provenance from mined legacy requirements into the two normative specs. It is not a competing source of truth.

## Archived Inputs

The previous per-family spec drafts are superseded inputs and live under [`archive/`](archive/):

| Archived folder | Prior role |
|---|---|
| `archive/core/` | Constitutional core draft, shared-ledger binding, and both legacy requirements matrices. |
| `archive/trust/` | Trust posture and key-lifecycle drafts. |
| `archive/projection/` | Projection runtime discipline draft. |
| `archive/export/` | Export package and disclosure manifest drafts. |
| `archive/operations/` | Monitoring and witnessing draft. |
| `archive/forms/` | Formspec respondent-history draft. |
| `archive/workflow/` | Workflow governance draft. |
| `archive/assurance/` | Assurance traceability draft. |

Treat archived files as historical source material. Do not cite them as normative unless a top-level spec explicitly incorporates a specific requirement.

## Checks

Run the Trellis spec lint after editing these documents:

```bash
python3 scripts/check-specs.py
python3 scripts/check-http-api-schema.py
```

The checks enforce stale Core-section references, forbidden legacy terms, requirement-ID sanity, archived-input placement, HTTP route drift, profile/version drift, and WOS event-literal registry drift.
