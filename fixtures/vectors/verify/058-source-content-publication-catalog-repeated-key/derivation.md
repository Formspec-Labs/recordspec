# Derivation — `verify/058-source-content-publication-catalog-repeated-key`

As `verify/028`, but the `063` row's `handoff` map is encoded by hand with a
second `responseHash` entry after the genuine one. A reader that keeps the first
copy would admit the row; canonical CBOR R4 refuses the whole catalog instead.
The catalog digest and the signed manifest are recomputed over the repeated bytes.
