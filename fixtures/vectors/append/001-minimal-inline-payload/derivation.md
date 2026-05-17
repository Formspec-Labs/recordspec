# Derivation — `append/001-minimal-inline-payload`

## Header

**What this vector exercises.** This vector is the genesis (`sequence = 0`) append to a fresh ledger scope `test-response-ledger`, carrying a 64-byte inline payload. It reproduces, byte-for-byte, every construction on the append critical path: the authored / canonical / signed event surfaces named in Core §6.8; the `author_event_hash` preimage and domain separation of §9.5 and §9.1; the `content_hash` over ciphertext bytes of §9.3; the RFC 9052 COSE_Sign1 protected header and `Sig_structure` of Core §7.4 with the pinned Phase 1 Ed25519 suite of §7.1; the `canonical_event_hash` of §9.2; and the `AppendHead` return artifact of §10.6. A reader with only Core in hand should be able to reconstruct every committed byte by hand.

**Scope of this vector.** This is a **structural-only** vector: the `PayloadInline.ciphertext` bstr carries the pinned 64-byte plaintext opaquely, and `KeyBag.entries` is the empty list (the CDDL `[* KeyBagEntry]` of §9.4 admits zero entries). No HPKE wrap is exercised here, because §9.4's freshness obligation for the ephemeral X25519 keypair cannot be satisfied by a reproducible fixture without additionally pinning the ephemeral keys; a later vector in this series carries a pinned ephemeral keypair and exercises real HPKE. The `content_hash` construction of §9.3 still runs over the bytes named by `payload_ref`, exactly as Core specifies, so the hashes-over-ciphertext discipline of §9.3 is preserved regardless of whether those ciphertext bytes are a real AEAD output or pinned opaque bytes.

**Pinned inputs.**

| Input | Value | Source |
|---|---|---|
| `signing_key` | Ed25519 COSE_Key, seed ending `…aa` | `../../_keys/issuer-001.cose_key` |
| `payload` | 64 bytes, ASCII `"Trellis fixture payload #001"` + `0x00` padding | `../../_inputs/sample-payload-001.bin` |
| `ledger_scope` | bstr `"test-response-ledger"` | §10.4 ledger scope; §10.6 `AppendHead.scope` |
| `sequence` | `0` (genesis) | §10.2: `prev_hash` MUST be `null` for `sequence == 0` |
| `timestamp` (`authored_at`) | `1745000000` | §12.1 `authored_at: uint` (Unix seconds UTC) |
| `event_type` | bstr `"x-trellis-test/append-minimal"` | §14.6 reserved test-identifier prefix |
| `classification` | bstr `"x-trellis-test/unclassified"` | §14.6 reserved test-identifier prefix |
| `retention_tier` | `0` | §12.1 `retention_tier: uint .size 1` |
| `idempotency_key` | bstr `"idemp-append-001"` (16 bytes) | §6.1 `idempotency_key: bstr .size (1..64)` |
| `suite_id` | `1` | §7.1 Phase 1 pin: Ed25519 / COSE_Sign1 |
| `PayloadInline.nonce` | 12 bytes of `0x00` | §6.4 `nonce: bstr .size 12` |

**Core § roadmap (in traversal order).**

1. §5.1 — dCBOR encoding profile. Every CBOR structure below is serialized per §5.1's byte-wise lexicographic canonical ordering.
2. §8.3 — `kid` derivation: `SHA-256(dCBOR_encode_uint(suite_id) || pubkey_raw)[0..16]`.
3. §9.3 + §9.1 — `content_hash` over the pinned `PayloadInline.ciphertext` bytes, domain-separated by `"trellis-content-v1"`.
4. §6.8 (authored form) + §9.5 — `AuthorEventHashPreimage` dCBOR-serialized; committed as `input-author-event-hash-preimage.cbor`.
5. §9.5 + §9.1 — `author_event_hash` preimage bytes (`trellis-author-event-v1` domain separation over step 4); SHA-256 digest.
6. §6.8 (canonical form) + §6.1 — `EventPayload` dCBOR-serialized; committed as `expected-event-payload.cbor`. This bstr is the COSE_Sign1 payload.
7. §7.4 — COSE protected-header map with `alg`, `kid`, `suite_id`, dCBOR-serialized, wrapped in a bstr.
8. §7.4 + RFC 9052 §4.4 — `Sig_structure = ["Signature1", protected_bstr, external_aad, payload_bstr]` with `external_aad = h''` per §6.6.
9. §7.1 — Ed25519 signature over the `Sig_structure` bytes.
10. §6.1 + §6.8 (signed form) + §7.4 — COSE_Sign1 tag-18 envelope; committed as `expected-event.cbor`.
11. §9.2 + §9.1 — `canonical_event_hash` over `dCBOR(CanonicalEventHashPreimage)` under `"trellis-event-v1"`.
12. §10.6 — `AppendHead = {scope, sequence, canonical_event_hash}` dCBOR-serialized; committed as `expected-append-head.cbor`.

---

## Body

### Step 1: dCBOR encoding profile

**Core § citation:** §5.1 Pinned encoding: dCBOR.

**Load-bearing sentence:**

> "All Trellis byte-level structures — events, checkpoints, signing-key registry entries, export manifests, inclusion proofs, consistency proofs — are serialized as **deterministic CBOR (dCBOR)**, which for this specification means the Core Deterministic Encoding profile of [RFC 8949] §4.2.2: Integers encoded in the smallest possible representation (no leading zero-length prefixes). Map keys sorted in byte-wise lexicographic order of their canonical CBOR encoding; duplicate keys rejected. No indefinite-length items (all arrays, maps, byte strings, text strings use definite-length encoding)."

**Operation:** Every CBOR encode operation below MUST satisfy §5.1. Concretely: maps are sorted by byte-wise lexicographic order over the canonical CBOR encoding of each key. For the 12 text-string keys common to `AuthorEventHashPreimage` (Step 4) and `EventPayload` (Step 6), the canonical CBOR encoding of each key and the resulting sort order are:

```
  66 68 65 61 64 65 72                               header
  67 6b 65 79 5f 62 61 67                            key_bag
  67 76 65 72 73 69 6f 6e                            version
  68 73 65 71 75 65 6e 63 65                         sequence
  69 70 72 65 76 5f 68 61 73 68                      prev_hash
  6a 65 78 74 65 6e 73 69 6f 6e 73                   extensions
  6b 63 61 75 73 61 6c 5f 64 65 70 73                causal_deps
  6b 63 6f 6d 6d 69 74 6d 65 6e 74 73                commitments
  6b 70 61 79 6c 6f 61 64 5f 72 65 66                payload_ref
  6c 63 6f 6e 74 65 6e 74 5f 68 61 73 68             content_hash
  6c 6c 65 64 67 65 72 5f 73 63 6f 70 65             ledger_scope
  6f 69 64 65 6d 70 6f 74 65 6e 63 79 5f 6b 65 79    idempotency_key
```

Where first bytes tie (e.g. the two `0x6b`-prefixed keys `causal_deps` / `commitments` and the two `0x6c`-prefixed keys `content_hash` / `ledger_scope`), byte-wise comparison continues into the next byte. `EventPayload` adds a 13th key, `author_event_hash` (canonical encoding starts `0x71 61 75…`), which sorts last.

The three integer keys of the protected-header map (`1`, `4`, `-65537`) encode as `0x01`, `0x04`, `0x3a00010000` and serialize in byte-wise order (`alg`, `kid`, `suite_id`).

---

### Step 2: Derive `kid` from `suite_id` and the issuer public key

**Core § citation:** §8.3 `kid` format → Derived `kid` construction (pinned).

**Load-bearing sentence:**

> "When a `kid` is derived, it MUST be the first 16 bytes of: `SHA-256( dCBOR_encode_uint(suite_id_integer) || pubkey_raw )` where: `dCBOR_encode_uint(x)` is the canonical dCBOR encoding of the unsigned integer `x` per §5.1 (smallest representation; for example, `suite_id = 1` encodes as the single byte `0x01`), `pubkey_raw` is the raw public-key bytes for the suite (for Phase 1 `suite_id = 1`, the 32-byte Ed25519 public key per [RFC 8032]), `||` denotes byte-string concatenation. Byte order is fixed: the dCBOR-encoded `suite_id` precedes `pubkey_raw`."

**Inputs:**

- `suite_id = 1` (§7.1). Its dCBOR encoding per §5.1 is the single byte `0x01`.
- `pubkey_raw` is the 32-byte Ed25519 public key from the pinned COSE_Key at `../../_keys/issuer-001.cose_key` — the value stored under COSE_Key label `-2` (`x`):

```
71de3b4e933aa718a6f5c45845ee83af8000a450f9572d4cf393e681c8144191
```

**Operation:** `kid = SHA-256(0x01 || pubkey_raw)[0..16]`.

**Result (16 bytes):**

```
af9dff525391faa75c8e8da4808b1743
```

**Committed as:** embedded in the COSE protected header (Step 7) and ultimately in `expected-event.cbor`. Not written to a sibling file in isolation — the `kid` bytes are fully determined by the inputs above and are reconstructible from them alone.

---

### Step 3: `content_hash` over `PayloadInline.ciphertext`

**Core § citation:** §9.3 Content hash (`trellis-content-v1`, over ciphertext); §9.1 Domain separation discipline.

**Load-bearing sentence (§9.3):**

> "`content_hash = SHA-256( "trellis-content-v1" domain-separated per §9.1 over the exact ciphertext bytes named by payload_ref )`. `content_hash` is over **ciphertext**, never plaintext."

**Load-bearing sentence (§9.1):**

> "Every hash computation in Trellis is domain-separated by a length-prefixed UTF-8 byte tag. The generic form is: `digest = SHA-256( len(tag) as 4-byte big-endian unsigned || tag as UTF-8 bytes || len(component) as 4-byte big-endian unsigned || component as raw bytes )`."

**Inputs:**

- `tag = "trellis-content-v1"` (§9.8 domain-tag registry, §9.3). UTF-8 length 18.
- `component = PayloadInline.ciphertext`. In this structural-only vector the ciphertext bstr carries the pinned 64-byte plaintext from `../../_inputs/sample-payload-001.bin` unchanged, as bytes (see scope of this vector, above). The bytes are ASCII `"Trellis fixture payload #001"` followed by 36 bytes of `0x00`:

```
5472656c6c69732066697874757265207061796c6f61642023303031
00000000000000000000000000000000000000000000000000000000
00000000
```

**Operation:**

```
preimage =   0x00 0x00 0x00 0x12        ; len(tag) = 18 as u32be
          || "trellis-content-v1"        ; UTF-8 bytes
          || 0x00 0x00 0x00 0x40        ; len(component) = 64 as u32be
          || <64 ciphertext bytes>

content_hash = SHA-256(preimage)
```

**Result (32 bytes):**

```
bcdced2dfaf5342cd2baca0560a9d384473fd45e202555f0654cccaa32b4f812
```

**Committed as:** embedded in the `author_event_hash` preimage and `EventPayload` committed below; reproducible from the inputs above.

---

### Step 4: Build `AuthorEventHashPreimage` (authored form per §6.8)

**Core § citation:** §6.8 Three event surfaces (authored form); §9.5 `author_event_hash` construction; Appendix A (§28) CDDL.

**Load-bearing sentence (§6.8):**

> "**Authored form.** The `AuthorEventHashPreimage` CDDL struct (§9.5). This is the event map an author constructs **before** computing `author_event_hash`: it carries every field that contributes to the author-originated integrity digest but does **not** carry `author_event_hash` itself, and carries no COSE signature material. Its dCBOR serialization is the input to the `trellis-author-event-v1` hash (§9.5). A fixture that pins 'the authored bytes' refers to `dCBOR(AuthorEventHashPreimage)`."

**Load-bearing CDDL (§9.5 / Appendix A):**

```cddl
AuthorEventHashPreimage = {
  version:         uint .size 1,
  ledger_scope:    bstr,
  sequence:        uint,
  prev_hash:       digest / null,
  causal_deps:     [* digest] / null,
  content_hash:    digest,
  header:          EventHeader,
  commitments:     [* Commitment] / null,
  payload_ref:     PayloadRef,
  key_bag:         KeyBag,
  idempotency_key: bstr .size (1..64),
  extensions:      { * tstr => any } / null,
}
```

**Field population (per the pinned inputs above):**

| Field | Value | Core citation |
|---|---|---|
| `version` | `1` | §6.1 wire-format version |
| `ledger_scope` | `"test-response-ledger"` (bstr, 20 bytes) | §6.1, §10.4 |
| `sequence` | `0` | §10.2 (genesis) |
| `prev_hash` | `null` | §10.2: "For `sequence == 0`: `prev_hash` MUST be `null`." |
| `causal_deps` | `null` | §10.3: "Phase 1 events MUST emit `causal_deps` as `null` or `[]`." |
| `content_hash` | 32 bytes from Step 3 | §9.3 |
| `header` | `EventHeader` map; see below | §12.1 |
| `commitments` | `null` | §13.3: "Phase 1 producers MUST emit `commitments` as `null` or `[]`." |
| `payload_ref` | `PayloadInline` map; see below | §6.4 |
| `key_bag` | `KeyBag` map with `entries: []` | §9.4 (empty admissible under `[* KeyBagEntry]`) |
| `idempotency_key` | `"idemp-append-001"` (16 bytes) | §6.1 `.size (1..64)` |
| `extensions` | `null` | §6.5 Phase 1 emission rule |

**`EventHeader` sub-map (§12.1):**

| Field | Value |
|---|---|
| `event_type` | `"x-trellis-test/append-minimal"` (bstr, 29 bytes) — §14.6 |
| `authored_at` | `1745000000` — §12.1 |
| `retention_tier` | `0` — §12.1 |
| `classification` | `"x-trellis-test/unclassified"` (bstr, 27 bytes) — §14.6 |
| `outcome_commitment` | `null` — §12.1 (no commitment in this vector) |
| `subject_ref_commitment` | `null` |
| `tag_commitment` | `null` |
| `witness_ref` | `null` — reserved for Phase 4 |
| `extensions` | `null` — §12.3 |

**`PayloadRef` sub-map (`PayloadInline`, §6.4):**

| Field | Value |
|---|---|
| `ref_type` | text string `"inline"` |
| `ciphertext` | 64 bytes from Step 3 |
| `nonce` | 12 bytes of `0x00` — §6.4 `bstr .size 12` |

**`KeyBag` sub-map (§9.4):** `{ "entries": [] }`.

**Operation:** dCBOR-encode the map (§5.1 byte-wise lex key ordering).

**Result (540 bytes):**

See the footer dump for `input-author-event-hash-preimage.cbor`. The first byte is `0xac` (map with 12 text-keyed entries). The 12 keys appear in byte-wise lex order of their canonical-CBOR encoding (see Step 1 for the full encoding-and-sort table): `header`, `key_bag`, `version`, `sequence`, `prev_hash`, `extensions`, `causal_deps`, `commitments`, `payload_ref`, `content_hash`, `ledger_scope`, `idempotency_key`. Full hex in the footer.

**Committed as:** `input-author-event-hash-preimage.cbor` (540 bytes).

---

### Step 5: `author_event_hash`

**Core § citation:** §9.5 `author_event_hash` construction; §9.1 Domain separation discipline.

**Load-bearing sentence:**

> "`author_event_hash = SHA-256( "trellis-author-event-v1" domain-separated per §9.1 over dCBOR(AuthorEventHashPreimage) )`. `author_event_hash` binds the envelope payload, payload reference, and key bag at the moment of signing. It excludes itself and all signature material by construction: `AuthorEventHashPreimage` has no `author_event_hash` field and no COSE signature field."

**Inputs:**

- `tag = "trellis-author-event-v1"` (UTF-8 length 23, per §9.8).
- `component = dCBOR(AuthorEventHashPreimage)` = bytes of `input-author-event-hash-preimage.cbor` from Step 4 (540 bytes).

**Operation:**

```
preimage =   0x00 0x00 0x00 0x17        ; len(tag) = 23
          || "trellis-author-event-v1"   ; UTF-8
          || 0x00 0x00 0x02 0x1c        ; len(component) = 540
          || <540 bytes of Step 4 output>

author_event_hash = SHA-256(preimage)
```

**Result (preimage, 571 bytes):** Committed as `author-event-preimage.bin`. First 8 bytes are `0x00 00 00 17 74 72 65 6c` = `[len=23][t r e l`.

**Result (digest, 32 bytes):**

```
d8c7c6fb6fdc99940ff8d801fb1b3231723c0e63fb78625c67e9b249014127b2
```

**Committed as:** preimage bytes as `author-event-preimage.bin`; digest as `author-event-hash.bin`.

---

### Step 6: Build `EventPayload` (canonical form per §6.8)

**Core § citation:** §6.8 Three event surfaces (canonical form); §6.1 Normative structure; Appendix A (§28) CDDL.

**Load-bearing sentence (§6.8):**

> "**Canonical form.** The `EventPayload` CDDL struct (§6.1). This is the full event map **including** the computed `author_event_hash`, ready to be signed. It contains no COSE signature bytes — signing is external to the payload. Its dCBOR serialization is the input to the `trellis-event-v1` hash (§9.2) — wrapped in `CanonicalEventHashPreimage` for domain separation — and is the exact payload bytes placed inside the COSE_Sign1 envelope. A fixture that pins 'the canonical bytes' refers to `dCBOR(EventPayload)`."

**Load-bearing CDDL (§6.1 / Appendix A):**

```cddl
EventPayload = {
  version:           uint .size 1,
  ledger_scope:      bstr,
  sequence:          uint,
  prev_hash:         digest / null,
  causal_deps:       [* digest] / null,
  author_event_hash: digest,
  content_hash:      digest,
  header:            EventHeader,
  commitments:       [* Commitment] / null,
  payload_ref:       PayloadRef,
  key_bag:           KeyBag,
  idempotency_key:   bstr .size (1..64),
  extensions:        { * tstr => any } / null,
}
```

**Field population:** identical to Step 4's `AuthorEventHashPreimage` *plus* the `author_event_hash` field set to the 32-byte digest from Step 5. All other fields are byte-identical to Step 4.

**Operation:** dCBOR-encode (§5.1).

**Result (592 bytes):** See footer dump for `expected-event-payload.cbor`. The first byte is `0xad` (map with 13 text-keyed entries — 12 from Step 4 plus `author_event_hash`).

**Committed as:** `expected-event-payload.cbor` (592 bytes). These are the bytes that will become the COSE_Sign1 `payload` bstr in Step 10.

---

### Step 7: Build the COSE protected-header bstr

**Core § citation:** §7.4 COSE protected headers and Sig_structure.

**Load-bearing sentence:**

> "For every Trellis COSE_Sign1 artifact, the protected header MUST contain: `alg` — Label (integer key) `1` (per [RFC 9052] §3.1) — COSE algorithm identifier. Phase 1: `-8` (EdDSA). `kid` — Label (integer key) `4` (per [RFC 9052] §3.1) — 16-byte signing-key identifier resolvable in `signing-key-registry.cbor` (§8). `suite_id` — Label (integer key) `-65537` — Trellis signature-suite identifier. Phase 1: `1`."

> "The protected header is itself a CBOR map wrapped in a bstr; its bytes determine the `Sig_structure` preimage and therefore the signature. The protected-header map MUST be serialized per the dCBOR rules of §5.1."

**Operation:** Build the map `{1: -8, 4: <kid-16B>, -65537: 1, -65538: "event"}`, serialize as dCBOR (§5.1 byte-wise lex key ordering), then wrap the resulting bytes in a CBOR bstr. §7.4 requires `artifact_type` (`-65538`) on every Trellis substrate envelope; append vectors use `"event"`.

**Integer-key ordering:** Per §5.1 map keys are sorted by byte-wise lexicographic order over their canonical CBOR encoding. The four keys encode as `0x01` (key `1`, major-type-0), `0x04` (key `4`, major-type-0), `0x3a00010000` (key `-65537`, major-type-1 with 4-byte argument), and `0x3a00010001` (key `-65538`, major-type-1 with 4-byte argument). Byte-wise `0x01 < 0x04 < 0x3a00010000 < 0x3a00010001`, so the serialized order is `alg`, `kid`, `suite_id`, `artifact_type`.

**Inner protected-header map bytes (38 bytes):**

```
a4                                                       ; map(4)
  01 27                                                  ; alg = -8 (EdDSA)
  04 50 af9dff525391faa75c8e8da4808b1743                 ; kid = 16B bstr from Step 2
  3a 00010000 01                                         ; suite_id = 1
  3a 00010001 65 6576656e74                              ; artifact_type = "event"
```

= `a401270450af9dff525391faa75c8e8da4808b17433a00010000013a00010001656576656e74` (38 bytes).

**Wrapped as bstr (protected bstr, 40 bytes):** prepend `0x58 0x26` (bstr, length 38):

```
5826 a401270450af9dff525391faa75c8e8da4808b17433a00010000013a00010001656576656e74
```

**Committed as:** embedded in `sig-structure.bin` and `expected-event.cbor`; fully reconstructible from Step 2's `kid` and this step's procedure.

---

### Step 8: Build `Sig_structure` per RFC 9052 §4.4

**Core § citation:** §7.4 step 5; §6.6 Signature scope.

**Load-bearing sentence (§7.4 step 5):**

> "Sign the RFC 9052 `Sig_structure` array `["Signature1", protected, external_aad, payload]`, with `external_aad` equal to the zero-length byte string for Phase 1."

**Load-bearing sentence (§6.6):**

> "`payload` is the exact dCBOR bytes of `EventPayload`. `external_aad` is the zero-length byte string for Phase 1."

**Operation:** Construct the 4-element CBOR array:

1. Text string `"Signature1"`.
2. The protected bstr from Step 7 — **wrapped as a bstr**, not as a nested CBOR map. RFC 9052 §4.4 defines the `Sig_structure` field as `bstr`, carrying the bytes of the protected header map.
3. `external_aad = h''` (zero-length bstr).
4. The `payload` bstr = `dCBOR(EventPayload)` bytes from Step 6 wrapped as a bstr.

Serialize the array as dCBOR (§5.1). Arrays are not key-sorted; their element order is fixed by RFC 9052.

**Result (648 bytes):** The array prefix is `0x84` (array of 4). First element is the text string `"Signature1"` (`0x6a5369676e6174757265 31` — major type 3, length 10). Second is the 38-byte inner protected bstr wrapped (`0x58 0x26` + 38 bytes). Third is `0x40` (zero-length bstr). Fourth is the 592-byte `EventPayload` bstr wrapped (`0x59 0x02 0x50` + 592 bytes).

**Committed as:** `sig-structure.bin` (648 bytes). Full dump in footer.

---

### Step 9: Ed25519 signature

**Core § citation:** §7.1 Pinned Phase 1 suite.

**Load-bearing sentence:**

> "Phase 1 pins `suite_id = 1` to Ed25519-over-COSE_Sign1. Concretely: the signature is COSE_Sign1 ([RFC 9052]) with `alg = -8` (EdDSA) and the signing key a 32-byte Ed25519 public key ([RFC 8032])."

**Inputs:**

- Signing seed: the 32 bytes under COSE_Key label `-4` at `../../_keys/issuer-001.cose_key` (`00...aa`).
- Message: the 635-byte `Sig_structure` bytes from Step 8.

**Operation:** Compute `signature = Ed25519-Sign(seed, Sig_structure_bytes)` per [RFC 8032] §5.1.6. Ed25519 is pure (no pre-hash): the signer consumes the message bytes as input to the internal SHAs defined in RFC 8032, not a pre-computed digest.

**Result (64 bytes):**

```
80f197b6e23b4dcf64fab17e6fc9cd373a379576995224a298cb8687e1a59992
4a1a6955bc695c6faf7b8ab578f6141acab2ab7cd5ef4ecce2abea7037ae290e
```

**Committed as:** embedded in `expected-event.cbor`; deterministic under RFC 8032 for fixed seed + fixed message.

---

### Step 10: Assemble the COSE_Sign1 tag-18 envelope (signed form per §6.8)

**Core § citation:** §6.8 Three event surfaces (signed form); §6.1 Normative structure; §7.4.

**Load-bearing sentence (§6.8):**

> "**Signed form (wire form).** The `Event = COSESign1Bytes` CDDL type (§6.1, §7.4). This is the COSE_Sign1 tag-18 envelope carrying the canonical form as its payload bstr, the Ed25519 signature over the RFC 9052 `Sig_structure`, and the protected-header map pinned by §7.4."

**Load-bearing sentence (§6.1):**

> "On the wire an event is a COSE_Sign1 object whose protected headers identify the signing suite and key, and whose payload is the dCBOR encoding of `EventPayload`."

**Operation:** Build the tagged 4-array per RFC 9052 §4.2:

```
COSE_Sign1 = 18([ protected_bstr, unprotected_map, payload_bstr, signature_bstr ])
```

where:

- `protected_bstr` is the 40-byte wrapped protected header from Step 7 (bstr carrying the 38 inner bytes).
- `unprotected_map` is the empty CBOR map `{}` — this vector carries no unprotected headers.
- `payload_bstr` is the 592-byte `EventPayload` from Step 6, wrapped as a bstr. Per §6.1 the payload is embedded (not detached).
- `signature_bstr` is the 64-byte Ed25519 signature from Step 9, wrapped as a bstr.

Apply CBOR tag 18 (`0xd2`) to the 4-array. Serialize as dCBOR.

**Result (704 bytes):** First 4 bytes are `0xd2 0x84 0x58 0x26` (tag 18, array of 4, bstr length 38). Full dump in footer.

**Committed as:** `expected-event.cbor` (704 bytes).

---

### Step 11: `canonical_event_hash`

**Core § citation:** §9.2 Canonical event hash (`trellis-event-v1`); §9.1.

**Load-bearing sentence:**

> "`canonical_event_hash = SHA-256( "trellis-event-v1" domain-separated per §9.1 over dCBOR(CanonicalEventHashPreimage) )`."

**Load-bearing CDDL (§9.2):**

```cddl
CanonicalEventHashPreimage = {
  version:       uint .size 1,
  ledger_scope:  bstr,
  event_payload: EventPayload,
}
```

**Inputs:**

- `tag = "trellis-event-v1"` (UTF-8 length 16, per §9.8).
- `component = dCBOR(CanonicalEventHashPreimage)`. The struct is `{version: 1, ledger_scope: "test-response-ledger", event_payload: <EventPayload from Step 6>}`. dCBOR-encode the 3-key map (§5.1); keys `"version"` (0x67), `"ledger_scope"` (0x6c), `"event_payload"` (0x6d) sort in byte-wise order `version, ledger_scope, event_payload`.

**Operation:**

```
component = dCBOR({ "version": 1,
                    "ledger_scope": b"test-response-ledger",
                    "event_payload": <EventPayload map from Step 6> })

preimage  = 0x00 0x00 0x00 0x10            ; len(tag) = 16
         || "trellis-event-v1"              ; UTF-8
         || <4-byte BE len(component)>
         || <component bytes>

canonical_event_hash = SHA-256(preimage)
```

**Result (32 bytes):**

```
bb2cdb1e0aa3bcae1d50cb72d68b26af45b92e088f820e901c3d6d1558694396
```

**Committed as:** embedded in `expected-append-head.cbor` (Step 12); reconstructible from Step 6 and this procedure.

---

### Step 12: Build `AppendHead`

**Core § citation:** §10.6 Append head artifact; Appendix A (§28) CDDL.

**Load-bearing sentence:**

> "Every successful `append` operation returns a structured **append head** describing the post-append state of the targeted ledger scope. [...] An `AppendHead` is serialized as dCBOR (§5.1). Its bytes are fully determined by the just-appended event's canonical form (§6.8); a verifier or a second implementation that recomputes `canonical_event_hash` for the same event and constructs the same `(scope, sequence, canonical_event_hash)` tuple will produce byte-identical `AppendHead` bytes."

**Load-bearing CDDL (§10.6):**

```cddl
AppendHead = {
  scope:                bstr,
  sequence:             uint,
  canonical_event_hash: digest,
}
```

**Field population:**

| Field | Value | Source |
|---|---|---|
| `scope` | `"test-response-ledger"` (bstr, 20 bytes) | equal to `EventPayload.ledger_scope` per §10.6 |
| `sequence` | `0` | equal to `EventPayload.sequence` per §10.6 |
| `canonical_event_hash` | 32 bytes from Step 11 | §9.2 |

**Operation:** dCBOR-encode the 3-key map (§5.1). Keys `"scope"` (0x65), `"sequence"` (0x68), `"canonical_event_hash"` (0x74) sort in byte-wise order `scope, sequence, canonical_event_hash`.

**Result (93 bytes):**

See footer dump for `expected-append-head.cbor`. First byte is `0xa3` (map with 3 entries).

**Committed as:** `expected-append-head.cbor` (93 bytes).

---

## Footer — full hex dumps

Each block below is the byte-exact content of the named sibling file. A reader can verify by running `xxd` (or equivalent) on the sibling and comparing.

### `input-author-event-hash-preimage.cbor` (540 bytes, sha256 `dcbcd94f4151af94d4e87ebb292a60c252f4559b7f4bb0dd8bed41069ec1db01`)

```
ac66686561646572a96a6576656e745f74797065581d782d7472656c6c69732d
746573742f617070656e642d6d696e696d616c6a657874656e73696f6e73f66b
617574686f7265645f6174821a68029640006b7769746e6573735f726566f66e
636c617373696669636174696f6e581b782d7472656c6c69732d746573742f75
6e636c61737369666965646e726574656e74696f6e5f74696572006e7461675f
636f6d6d69746d656e74f6726f7574636f6d655f636f6d6d69746d656e74f676
7375626a6563745f7265665f636f6d6d69746d656e74f6676b65795f626167a1
67656e7472696573806776657273696f6e016873657175656e63650069707265
765f68617368f66a657874656e73696f6e73f66b63617573616c5f64657073f6
6b636f6d6d69746d656e7473f66b7061796c6f61645f726566a3656e6f6e6365
4c000000000000000000000000687265665f7479706566696e6c696e656a6369
706865727465787458405472656c6c69732066697874757265207061796c6f61
6420233030310000000000000000000000000000000000000000000000000000
000000000000000000006c636f6e74656e745f686173685820bcdced2dfaf534
2cd2baca0560a9d384473fd45e202555f0654cccaa32b4f8126c6c6564676572
5f73636f706554746573742d726573706f6e73652d6c65646765726f6964656d
706f74656e63795f6b6579506964656d702d617070656e642d303031
```

### `author-event-preimage.bin` (571 bytes, sha256 `d8c7c6fb6fdc99940ff8d801fb1b3231723c0e63fb78625c67e9b249014127b2`)

```
000000177472656c6c69732d617574686f722d6576656e742d76310000021cac
66686561646572a96a6576656e745f74797065581d782d7472656c6c69732d74
6573742f617070656e642d6d696e696d616c6a657874656e73696f6e73f66b61
7574686f7265645f6174821a68029640006b7769746e6573735f726566f66e63
6c617373696669636174696f6e581b782d7472656c6c69732d746573742f756e
636c61737369666965646e726574656e74696f6e5f74696572006e7461675f63
6f6d6d69746d656e74f6726f7574636f6d655f636f6d6d69746d656e74f67673
75626a6563745f7265665f636f6d6d69746d656e74f6676b65795f626167a167
656e7472696573806776657273696f6e016873657175656e6365006970726576
5f68617368f66a657874656e73696f6e73f66b63617573616c5f64657073f66b
636f6d6d69746d656e7473f66b7061796c6f61645f726566a3656e6f6e63654c
000000000000000000000000687265665f7479706566696e6c696e656a636970
6865727465787458405472656c6c69732066697874757265207061796c6f6164
2023303031000000000000000000000000000000000000000000000000000000
0000000000000000006c636f6e74656e745f686173685820bcdced2dfaf5342c
d2baca0560a9d384473fd45e202555f0654cccaa32b4f8126c6c65646765725f
73636f706554746573742d726573706f6e73652d6c65646765726f6964656d70
6f74656e63795f6b6579506964656d702d617070656e642d303031
```

Note: bytes 0..3 are `00 00 00 17` (length-prefix, 23) and bytes 4..26 are `"trellis-author-event-v1"`; bytes 27..30 are `00 00 02 1c` (length-prefix, 540) and bytes 31..570 reproduce `input-author-event-hash-preimage.cbor` verbatim.

### `author-event-hash.bin` (32 bytes, sha256 `433887f11540efeed73c33c5338af0ff97362fe59a5b50d95a7354c7c79bcd8c`)

```
d8c7c6fb6fdc99940ff8d801fb1b3231723c0e63fb78625c67e9b249014127b2
```

This is the SHA-256 of `author-event-preimage.bin`; i.e., the file *is* the author_event_hash value. The file's own SHA-256 (shown above) is a second-order integrity check only.

### `expected-event-payload.cbor` (592 bytes, sha256 `e957fcb7aa71bd16a4b4e7cfb5e7062ef0a91bf47cb882086fe03959bdc109e1`)

```
ad66686561646572a96a6576656e745f74797065581d782d7472656c6c69732d
746573742f617070656e642d6d696e696d616c6a657874656e73696f6e73f66b
617574686f7265645f6174821a68029640006b7769746e6573735f726566f66e
636c617373696669636174696f6e581b782d7472656c6c69732d746573742f75
6e636c61737369666965646e726574656e74696f6e5f74696572006e7461675f
636f6d6d69746d656e74f6726f7574636f6d655f636f6d6d69746d656e74f676
7375626a6563745f7265665f636f6d6d69746d656e74f6676b65795f626167a1
67656e7472696573806776657273696f6e016873657175656e63650069707265
765f68617368f66a657874656e73696f6e73f66b63617573616c5f64657073f6
6b636f6d6d69746d656e7473f66b7061796c6f61645f726566a3656e6f6e6365
4c000000000000000000000000687265665f7479706566696e6c696e656a6369
706865727465787458405472656c6c69732066697874757265207061796c6f61
6420233030310000000000000000000000000000000000000000000000000000
000000000000000000006c636f6e74656e745f686173685820bcdced2dfaf534
2cd2baca0560a9d384473fd45e202555f0654cccaa32b4f8126c6c6564676572
5f73636f706554746573742d726573706f6e73652d6c65646765726f6964656d
706f74656e63795f6b6579506964656d702d617070656e642d30303171617574
686f725f6576656e745f686173685820d8c7c6fb6fdc99940ff8d801fb1b3231
723c0e63fb78625c67e9b249014127b2
```

(The final 35 bytes, `71 617574686f725f6576656e745f68617368 5820 <32-byte digest>`, carry the text key `"author_event_hash"` (CBOR major-type-3, length 17) and its digest bstr value. The map header is `0xad` (major type 5, length 13) rather than the `0xac` (length 12) of `input-author-event-hash-preimage.cbor` because `EventPayload` has this one additional key.)

### `sig-structure.bin` (648 bytes, sha256 `27269410ad0e902bef33cbecb570fe07e854f92c0949734372383661e51f5bd5`)

```
846a5369676e6174757265315826a401270450af9dff525391faa75c8e8da480
8b17433a00010000013a00010001656576656e7440590250ad66686561646572
a96a6576656e745f74797065581d782d7472656c6c69732d746573742f617070
656e642d6d696e696d616c6a657874656e73696f6e73f66b617574686f726564
5f6174821a68029640006b7769746e6573735f726566f66e636c617373696669
636174696f6e581b782d7472656c6c69732d746573742f756e636c6173736966
6965646e726574656e74696f6e5f74696572006e7461675f636f6d6d69746d65
6e74f6726f7574636f6d655f636f6d6d69746d656e74f6767375626a6563745f
7265665f636f6d6d69746d656e74f6676b65795f626167a167656e7472696573
806776657273696f6e016873657175656e63650069707265765f68617368f66a
657874656e73696f6e73f66b63617573616c5f64657073f66b636f6d6d69746d
656e7473f66b7061796c6f61645f726566a3656e6f6e63654c00000000000000
0000000000687265665f7479706566696e6c696e656a63697068657274657874
58405472656c6c69732066697874757265207061796c6f616420233030310000
0000000000000000000000000000000000000000000000000000000000000000
00006c636f6e74656e745f686173685820bcdced2dfaf5342cd2baca0560a9d3
84473fd45e202555f0654cccaa32b4f8126c6c65646765725f73636f70655474
6573742d726573706f6e73652d6c65646765726f6964656d706f74656e63795f
6b6579506964656d702d617070656e642d30303171617574686f725f6576656e
745f686173685820d8c7c6fb6fdc99940ff8d801fb1b3231723c0e63fb78625c
67e9b249014127b2
```

Structure (per RFC 9052 §4.4): `0x84` (array of 4); `0x6a "Signature1"` (text string, 10 bytes); `0x58 0x26 <38-byte protected header>`; `0x40` (zero-length external_aad bstr); `0x59 0x02 0x50 <592-byte EventPayload>`.

### `expected-event.cbor` (704 bytes, sha256 `deca82133a10729c570e277ee38a975b7f6b9e79374052f80069b3863bdd733d`)

```
d2845826a401270450af9dff525391faa75c8e8da4808b17433a00010000013a
00010001656576656e74a0590250ad66686561646572a96a6576656e745f7479
7065581d782d7472656c6c69732d746573742f617070656e642d6d696e696d61
6c6a657874656e73696f6e73f66b617574686f7265645f6174821a6802964000
6b7769746e6573735f726566f66e636c617373696669636174696f6e581b782d
7472656c6c69732d746573742f756e636c61737369666965646e726574656e74
696f6e5f74696572006e7461675f636f6d6d69746d656e74f6726f7574636f6d
655f636f6d6d69746d656e74f6767375626a6563745f7265665f636f6d6d6974
6d656e74f6676b65795f626167a167656e7472696573806776657273696f6e01
6873657175656e63650069707265765f68617368f66a657874656e73696f6e73
f66b63617573616c5f64657073f66b636f6d6d69746d656e7473f66b7061796c
6f61645f726566a3656e6f6e63654c000000000000000000000000687265665f
7479706566696e6c696e656a6369706865727465787458405472656c6c697320
66697874757265207061796c6f61642023303031000000000000000000000000
0000000000000000000000000000000000000000000000006c636f6e74656e74
5f686173685820bcdced2dfaf5342cd2baca0560a9d384473fd45e202555f065
4cccaa32b4f8126c6c65646765725f73636f706554746573742d726573706f6e
73652d6c65646765726f6964656d706f74656e63795f6b6579506964656d702d
617070656e642d30303171617574686f725f6576656e745f686173685820d8c7
c6fb6fdc99940ff8d801fb1b3231723c0e63fb78625c67e9b249014127b25840
68f6df03a639f36dc6c71acf6e70939f0f49f00a39a6b9b882719449cb65e45e
94e6954728c6e2c7f3fbbebe522095137683e0ddf320b965feffa4e2faff890c
```

Structure: `0xd2` (tag 18); `0x84` (array of 4); `0x58 0x26 <38-byte protected>`; `0xa0` (empty unprotected map); `0x59 0x02 0x50 <592-byte payload>`; `0x58 0x40 <64-byte signature>`.

### `expected-append-head.cbor` (93 bytes, sha256 `a0145575789b60103916b7c9466860dd279f1dcb1087fbf09b67a5e24ef6dc40`)

```
a36573636f706554746573742d726573706f6e73652d6c656467657268736571
75656e6365007463616e6f6e6963616c5f6576656e745f686173685820bb2cdb
1e0aa3bcae1d50cb72d68b26af45b92e088f820e901c3d6d1558694396
```

Structure: `0xa3` (map of 3); `0x65 "scope" 0x54 <20-byte ledger_scope>`; `0x68 "sequence" 0x00`; `0x74 "canonical_event_hash" 0x58 0x20 <32-byte digest>`.
