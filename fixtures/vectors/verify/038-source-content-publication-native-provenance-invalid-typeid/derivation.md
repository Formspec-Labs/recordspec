# Derivation — `verify/038-source-content-publication-native-provenance-invalid-typeid`

The bundle extends the public-intake export with two native task records
(`taskCreated`, `taskCompleted`) as generic `wos.provenance.recorded` events.
`062` carries one closed `sourceSignedCompletedTask` row of the mixed family
whose protected package locator is bound to the task's protected Response, and
`063` carries the protected original with an `original_context_proof` naming
that package. All ciphertext, keys and Source proofs are fake: the publication
phase checks closed shapes and exact native joins only.

The `taskCreated` record's `id` is not a record-family TypeID.
