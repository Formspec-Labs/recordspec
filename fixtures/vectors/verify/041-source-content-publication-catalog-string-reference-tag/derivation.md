# Derivation — `verify/041-source-content-publication-catalog-string-reference-tag`

As `verify/028`, but `063-intake-handoffs.cbor` is the protected catalog wrapped
in tag 256. A decoder that resolves reference tags would read the same rows;
the canonical profile never emits the tag, so the catalog is refused.
