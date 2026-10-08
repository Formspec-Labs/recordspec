# D1 Trellis writer qualification candidate

Status: authored desired candidate; no full D1 case export or signed manifest created.

This is a review document, not a new API or manifest format. Integrity owns the single schema-native bundle-creation and offline-verifier input. Bindings owns accepted Response bytes, signed text, actor association and append calls. Trellis owns deterministic writer composition and native retrieval.

The single complete verifier candidate is `../thoughts/plans/benefits-scenarios/execution/reports/integrity-stack/full-d1-export/complete-export-verifier-candidate.json`. Integrity owns its version and exact review pins; consult that owner’s certificate before execution. Its schema-native `bundle-create-request.json` is Integrity-owned; this slice adds no duplicate wire body. These are mutable authored candidates, not signed export bytes.

## Input and acceptance boundary

Full Need import SHA-256: `2b349b10fda5618543d0aa6dcd79ee1632e87c593c5f43edc89a2cdc3a7b88b8`; 39 Needs. The 0.3.0 authored form/workflow remains mutable. Baseline case `420804727`, ledger `urn:wos:default_case_01m4ec9nt2fygbtz7gqaq0rhab`, has only initial pending-review evidence. Its accepted response and photo cannot stand in for a completed 0.3.0 case.

The explicit Presenter export action runs after a decision and includes the latest authorized case history, including late evidence and reasoned reopening when present. No workflow on-entry action automatically seals a final bundle. A later append changes the head; retain the checkpoint pin and retrieve that same pin for reproducibility. Field visibility comes from the authenticated reader grant and consumer policy, not a whole-scope download assumption.

## Native member coverage desired before qualification

| Member | Required evidence when applicable | Current writer input |
| --- | --- | --- |
| `000`–`050` | Signed manifest/events, inclusion and consistency proofs, signing-key and event registries, checkpoints | Supported |
| `060-payloads/` | Readable or encrypted document/photo/signed-text bytes with declared omissions | No writer input/member emission found |
| `061-attachments.cbor` | Original and replacement attachment bindings, exact content hashes | No writer input/member emission found |
| `062-signature-affirmations.cbor` | Signer, signed text, consent/paper option, signing time and identification method | No writer input/member emission found |
| `063-intake-handoffs.cbor` | Accepted canonical Response and handoff bytes | No writer input/member emission found |
| `065-certificates-of-completion.cbor` | Genuine completion event plus presentation artifact and signing-event links | No writer input/member emission found |
| `066-signed-acts.cbor` / `068-signed-acts-manifest.cbor` | Derived signed acts and sealed source-event tuples | Optional typed inputs supported; server derives applicable catalogs through `build_export_profile_members` |
| `067-policy-closure.cbor` | Case admission-policy evidence, excluding trust-root/runtime configuration | Optional typed input supported; server derives applicable policy closure through `build_export_profile_members` |
| `open-clocks.json` | Chain-derived current open clocks; closed clock history remains in signed events | No writer input/member emission found |

Source: `specs/trellis-core.md` §§18.2–18.3,19 and `crates/trellis-export-writer/src/lib.rs` `ExportWriterInput` / `write_export`; `crates/trellis-server/src/lib.rs` `publish_bundle`. Missing optional members are a consumer qualification gap, not proof that every Trellis export must contain them. Do not insert catalogs without the sealed source events they derive from. Sample retention is consumer evidence; no invented top-level Trellis retention field.

## Full Need graph review index

Every Need remains in scope. The entries below retain each exact Done statement; they are desired evidence, not fulfilled results. Integrity maps them into its single verifier candidate. R12/X6/X14 require history completeness and offline checks; X4 restricts field visibility; X12 requires exact signed bytes; R11/X5 require late/reopen evidence when present.

### `review-and-sign-demo-response` — Review and sign a complete demo response

I see the full text and paper option, give electronic consent, and take a distinct signing action; the record keeps the signed text, signer, time and identification method

### `complete-demo-renewal-response` — Complete the fictional renewal response

I receive feedback about missing answers and cannot continue when required renewal information, including the Social Security number or sworn never-issued statement, is missing.

### `attach-demo-renewal-photo` — Provide the demo renewal photo

I can take or upload the photo and see the published-rule check result before submission.

### `understand-demo-privacy` — Read the demo privacy information

I can read the privacy information and the Social Security number requirement, and recognize unqualified sample wording rather than mistake it for approved legal text.

### `review-demo-paper-option` — Read the demo paper or in-person option

The alternative is visible; reviewing option information does not sign, submit, print or mail a response.

### `recognize-demo-sample-limits` — Recognize the fictional sample limits

I can recognize sample rules and fictional data, without being led to believe that the demonstration establishes an identity level or legal signature validity.

### `start-demo-application-early` — Start an application before final submission

When early Start is available, I can start from my owned recorded answers and see the confirmed application reference; final signing and submission remain separate.

### `control-demo-progress-persistence` — Understand whether progress can be resumed

When saving for later is available, I can save progress and see its actual result. Otherwise, controls and feedback describe the signing copy and do not promise later resume.

### `x1` — Reset the demonstration to a clean state

(all) Run on one laptop from a clean state, and reset to that state with one action between runs.

### `x2` — Recognize fictional people and data

(all) Use the four named people; every identifier is visibly fake (emails at example.com); no real person's data.

### `x3a` — Understand the case status at each step

(all) Show the applicant a plain-language status at every step.

### `x3c` — Find free language help in every notice

(all but D5) Every notice carries a short line in the program's other languages saying free help is available.

### `x3d` — Receive later notices in the preferred language

(all but D5) Record the applicant's preferred language and use it for every later notice.

### `x4` — Review the permitted case record in one screen

(all but D5) Show the reviewer one screen per case: answers, documents, outside data (each item with its source, its date, and "not yet confirmed with the applicant" until it is), and history. Each demo lists the fields each role sees, and a test proves no other field renders.

### `x5` — Trace each action and decision reason

(all) Record who did what and when for every step, and for every decision why, and show it in the record.

### `x6` — Check the exported record without the agency system

(all but D5) End with the proof moment: with the network off, the verifier confirms the bundle is complete and unchanged since the agency exported it, and names each signer. Its report says what it checked and what it cannot judge.

### `x7` — Follow the whole journey with truthful compressed clocks

(all) Run the script in about 90 seconds without narration. Faster time changes the clock's speed, never the number of days a rule gives; due dates show as calendar dates.

### `x8` — Complete every task accessibly

(all) Every applicant and reviewer screen meets WCAG 2.1 AA, the accessibility standard state and local web services must meet, across the whole flow: the automated check passes, plus a keyboard-only walk-through and a screen-reader walk-through with VoiceOver and NVDA.

### `x9` — Understand the limits of the claims

(all) Make no claim the demo cannot keep: sample rules are labeled as samples, "likely qualify" is never "eligible", and no identity level, legal validity or court admissibility is claimed.

### `x10` — Read consistently structured notices and correct rights

(all but D5) Every notice uses the fixed headings in the shared-wording table. Only decisions include "If you disagree"; send-backs include "If you can't get this, tell us and we'll help." D1's no-response denial has no hearing right and says so; D6's report review has no appeal, so its notices say "If you disagree: reply to the memo item".

### `x11` — Understand the personal-data request

(D1, D2) A federal demo that collects personal data shows a Privacy Act statement: the law that allows it, the purpose, who else may see it, and what happens if the applicant declines. Any demo that asks for a Social Security number says whether it is mandatory and why.

### `x12` — Assent to the exact complete text

(all but D5) Each signer sees the full text, agrees to sign electronically with paper offered, and takes a distinct signing action. The record keeps the signed text, the signer, the time, and how the signer was identified.

### `x13` — Dispute outside-data errors before adverse use

(D1, D3, D4) Outside data never counts against the applicant until a notice has told them and the dispute period (sample: 10 days) has passed.

### `x14` — Know the record-retention rule

(all but D5) The export says how long the record is kept and under which rule, labeled as a sample: "Kept at least 3 years (sample; set by the program's schedule)." D6 cites the program's own retention rule instead, labeled as a sample where the program sets none.

### `x15` — Choose paper or in-person service

(all) Each demo says the service is also available on paper or in person.

### `x16` — Understand demo sign-in and real identity alternatives

(all) The sign-in screen says: "Demo sign-in. A real program sets its identity level by risk and offers a way to prove identity without a computer." An emailed link never signs anyone in by itself.

### `d1-r1` — Complete required renewal answers

The form must validate as the applicant types and must not submit with required fields empty, including the Social Security number or the sworn never-issued statement.

### `d1-r2` — Provide a suitable passport photo

The applicant must be able to take or upload a photo, and an automated check against the published photo rules must show pass or what to fix before submission.

### `d1-r3` — Sign and receive the application reference

Submit must require the signed declaration and return a 9-digit reference number.

### `d1-r4` — Review automatically obtained outside checks

The prior-passport and Social Security checks must run without a person triggering them and must record source, time and result on the case.

### `d1-r5` — Know the requested items and real reply date

A send-back must name the items wanted and the reason, and start a 90-day clock from the notice date. Accepted O-15 starts the clock only at a qualifying recorded notice-sent event.

### `d1-r6` — Understand and answer the photo send-back

The send-back notice must carry the reference number, the request, a photo example, the send-by date and how to respond. Accepted O-15 starts the clock only at a qualifying recorded notice-sent event.

### `d1-r7` — Correct only the requested photo in the filed application

The task must reopen the application as filed with only the requested items unlocked; every earlier answer stays visible and cannot be changed.

### `d1-r8` — Resume review with the photo changes visible

A response must return the case to the reviewer's queue, flagged, with the status "Information Received, In Process Again" and a what-changed view.

### `d1-r9` — Understand a reasoned denial

A denial must produce a notice that states the specific reasons.

### `d1-r10` — Receive automatic no-response closure and reapplication instructions

An expired clock must close the case as denied for no response, with the new-application instruction and no hearing right. Accepted O-05 requires automatic expiry closure; no manual reviewer action substitutes for expiry.

### `d1-r11` — Retain late evidence without unauthorized reopening

A late response must attach to the case; reopening needs a reviewer and a recorded reason.

### `d1-r12` — Verify the complete passport case offline

The verifier's report must list the checks, the send-back, the response, the decision, the clock and every notice sent.

### `d1-r13` — Screen renewal eligibility before the form

An eligibility screen must run before the form.

## Executable checks and remaining gates

Run only committed fixture ZIPs through the existing Rust CLI and independent Python verifier. Record binary/input/source digests and complete outputs. These fixtures test maintained integrity/catalog behavior; they contain synthetic fixture identities and are never D1 accepted records. Existing-binary results do not prove the current Rust source was rebuilt.

Root executes `retrieval.http` privately only after review. Preserve ZIPs and case payloads outside Git; publish only redacted receipts and public pins. A successful head retrieval does not establish authorized field filtering, external trusted-key verification, complete 0.3.0 history, or durable storage. An independently supplied seal public-key pin remains Integrity-owned and unqualified until the verifier consumes it.

A generic writer fix needs a failing native emission check for the chosen existing catalog/member plus independent code and architecture review. Cargo activation and runtime changes remain root-owned. Do not add a D1-specific payload, backend, fabricated certificate or alternative export pipeline.

## Observed fixture results

The existing Rust verifier passed all five selected committed export fixtures (001, 005, 006, 007 public-create, 010). The independent Python verifier passed fixture 010 structure, integrity and readability checks, resolved its completion-certificate links, and reported the existing advisory that the signed scope lacks policy closure. The first Python attempt failed because the source package was not on `PYTHONPATH`; the retry set that path without installing or changing dependencies. Both attempts remain in the receipt. Fixture results establish catalog verification behavior, not current writer emission or D1 completeness.
