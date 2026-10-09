# Current authorization before append replay

Status: private implementation passed the exact native RED/GREEN probes. Final independent full AFTER review and owner adoption remain pending. Original service, keys, history and source tree are unchanged.

The baseline replay middleware returns a cached append receipt before the handler authenticates the current request. Both actual RED tests compiled and failed at the intended boundary: a missing bearer token received 201 instead of 401, and a bearer token without the requested scope received 201 instead of 403. RED recorded zero passes and two expected failures.

The private correction checks current authentication and host authorization before replay lookup on every retry. The existing authorizer receives the verified identity, full tenant/workspace/environment/cell tuple, requested action, and exact validated append body. It resolves an internal principal and grants the exact operation; the HTTP boundary refuses empty principals or a different tuple. The maintained replay partition uses that principal and full resource/action context. Raw original request bytes still determine the replay hash.

External token mode injects the maintained AccessTokenVerifier interface without local-token fallback. A real host requiring revocation must select OidcCurrentAuthority and authoritative principal, resource and actor-delegation grants. The tests use an explicitly controlled current-verifier and grant implementation; they do not qualify a real identity provider, actual issuer/audience configuration, production grants, or live deployment. Explicit existing local-token/development modes preserve their declared posture.

Head publication and pinned-bundle fallback publication require both Read and Administer for the SAME admitted internal principal. Existing pinned bundle reads require Read. Bounded parsing retains Axum JSON rejection behavior and passes the same parsed body to the append handler.

Actual GREEN compiled and passed all fourteen selected tests, including both original RED tests. The remaining checks cover current-verifier rejection/unavailability, revoked resource grants, revoked delegation for the unchanged cached body, each foreign tenant component, foreign transport actor and payload human, invalid authorizer results, two admitted principals reaching the actual replay driver, raw-body hash conflicts, JSON 415/400/422/413 refusal without append, existing pinned reads, head/pinned-miss publication denial, same-principal publication and explicit host-authorizer selection. No broader test run is claimed.

RED took 124.84 seconds and GREEN 6.59 seconds including compilation. These are diagnostic timings with different cache states, not a performance comparison. The improvement is authorization correctness and reuse of the existing authorizer/replay interfaces. Each retry now incurs current verification, permission checking and bounded body parsing; that is the intended security tradeoff.

Execution receipts retain exact command, environment, source/fixture pins, original/resolved lockfiles, log digest and owned process cleanup. Both process groups were absent and reaped; starting lock 34de1753... was restored in each private candidate and the original checkout. Source guards reported no drift. The minimal lock amendments change only existing dependency edges; package versions are unchanged.

Retained prerequisite failures remain explicit: RED v1 stopped on duplicate package paths; RED v2 stopped on nested workspace roots. Neither was behavioral RED. V3 metadata first required the existing async-trait dependency edge, then passed under the retained minimal amendment before the actual test run.

This correction does not qualify full D1 custody, evidence members, issued notices, actual Source signing history, export trust or disclosure authority. Native provenance routing and the first-publication evidence provider are separate owning work.
