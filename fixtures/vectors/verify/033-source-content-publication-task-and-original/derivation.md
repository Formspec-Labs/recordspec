# Derivation — `verify/033-source-content-publication-task-and-original`

The bundle extends the public-intake export with two native task records
(`taskCreated`, `taskCompleted`) as generic `wos.provenance.recorded` events.
`062` carries one closed `sourceSignedCompletedTask` row of the mixed family
whose protected package locator is bound to the task's protected Response, and
`063` carries the protected original with an `original_context_proof` naming
that package. All ciphertext, keys and Source proofs are fake: the publication
phase checks closed shapes and exact native joins only.

Every join holds, so the publication phase admits the bundle.
