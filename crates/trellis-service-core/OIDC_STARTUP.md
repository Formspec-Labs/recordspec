# Current OIDC startup

The CLI requires `TRELLIS_OIDC_CONFIG_FILE` before it reads signing keys or opens
storage. It refuses `TRELLIS_JWT_HS256_SECRET` and
`TRELLIS_PERMISSIVE_SCOPE_AUTH`, including empty values. Programmatic verifier
and authorizer injection remains available for tests and host composition.

The profile, introspection secret, and current grants must be regular files owned
by the server user, with no group or other permissions (for example, `0600`).
The server checks the opened file descriptor, refuses final-component symlinks,
and bounds each read to 1 MiB. This custody policy currently supports Unix only.
Keep parent directories under operator control. Replace grants atomically with a
complete private file; partial or invalid files deny requests with HTTP 503.

The following example contains public placeholders. Obtain the actual provider
subject and actor identities independently before selecting grants.

```json
{
  "issuer": "https://identity.example/realms/deployment",
  "audience": "trellis-api",
  "requiredScopes": ["trellis.access"],
  "allowedClients": ["producer-client"],
  "profile": "keycloak",
  "allowDevelopmentLoopbackHttp": false,
  "introspectionEndpoint": "https://identity.example/realms/deployment/protocol/openid-connect/token/introspect",
  "introspectionClientId": "trellis-introspection",
  "introspectionClientSecretFile": "introspection.secret",
  "grantsFile": "current-grants.json",
  "tenantScope": {
    "tenant": "tenant-a", "workspace": "workspace-a",
    "environment": "prod", "cell": "cell-a"
  },
  "identities": [{
    "issuer": "https://identity.example/realms/deployment",
    "subject": "provider-selected-subject",
    "clientId": "producer-client",
    "principal": "stable-internal-producer"
  }],
  "actionScopes": {
    "read": "trellis.read", "append": "trellis.append",
    "administer": "trellis.administer"
  }
}
```

Supported claim profiles are `keycloak`, `oktaCustomAuthorizationServer`, and
`rfc9068`. HTTPS is required unless development literal-loopback HTTP is selected.
Relative secret and grant paths resolve against the profile directory. Configure
the dedicated introspection client using the provider's audience requirements;
Keycloak may require that client's ID in the access token audience as well as
`trellis-api`. The maintained verifier checks signature, issuer, audience, client,
lifetime, base scopes, and current introspection before resource authorization.

The grant file repeats the exact deployment tuple:

```json
{
  "tenantScope": {
    "tenant": "tenant-a", "workspace": "workspace-a",
    "environment": "prod", "cell": "cell-a"
  },
  "grants": [{
    "principal": "stable-internal-producer",
    "scope": "operator-selected-case",
    "action": "append",
    "actors": [{"kind": "service", "subject": "producer-actor"}],
    "payloadActors": [{
      "pointer": "/record/actorId", "required": true,
      "subjects": ["operator-selected-human"]
    }]
  }, {
    "principal": "stable-internal-producer",
    "scope": "operator-selected-case", "action": "read"
  }]
}
```

Each request must match the fixed deployment tuple, mapped principal, exact scope,
and action-specific OAuth scope. Append also requires an exact actor kind and
subject. Payload selectors are JSON pointers relative to the event payload;
the producer owner selects paths for its data shape. Required selectors must
contain allowed text subjects. Optional selectors may be absent; present values
must still match. Compute disclosures do not grant delegation.

The closed deserialization types reject unknown or duplicate fields. Validation
rejects duplicate rows, unknown principals, ambiguous actors or selectors, and
actor rules on actions other than append. Read and administer use separate rows;
head publication requires both. Missing grants return HTTP 403. The server
reloads and validates the entire grant file for every authorization, including
idempotent retries. It does not cache positive grants.

Bind one dedicated database permanently to this profile's deployment tuple.
Changing the tuple while reusing stored scopes is unsupported. The operator must
maintain this association; startup does not persist or verify a database binding.
The grant file is operator authority for this deployment, not proof of canonical
rights or legal delegation. Case creation does not automatically register grants.

Outbound callers can inject the maintained
`ClientCredentialsTokenProvider` with
`TrellisServiceClient::with_token_provider`. The caller owns provider, credentials,
audience, scopes, and renewal. The client acquires once per request, refuses a
simultaneous static bearer, sends no request after acquisition failure, and
refuses redirects. Debug output redacts configured bearer values.

Verification includes actual CLI refusal tests, maintained RS256/discovery/JWKS/
introspection protocol fixtures, current-grant and unchanged-retry negatives,
and all five outbound client operations. Test execution and host startup require
the separately allocated build and runtime window.


The same private OIDC profile may select accepted-attachment custody through
`acceptedAttachmentRecipients`. Omit this field when the deployment does not
need accepted attachments. An explicitly selected empty list or null fails startup.
Each row contains exactly `principal`, `scope`, and `recipients`; each recipient
contains exactly `id` (UTF-8 key-version ID), `publicKey` (32 JSON byte values for
an existing X25519 public key), and `operatorHeld` (boolean). The row inherits
`tenantScope` from this profile and selects an exact admitted principal and
ledger scope. Supply public keys only; private reader keys stay with their owner.

Startup rejects unknown principals, invalid ledger scopes, duplicate rows,
empty or oversized lists, empty, whitespace-only, control-containing, or oversized IDs, zero keys, duplicate recipient
IDs or keys, and selections without a designated nonoperator reader. These
failures report `accepted-attachment recipient selection invalid` before signing
keys or storage open. Limits are 1024 rows, 64 recipients per row, and 256 bytes
per recipient ID, within the existing 1 MiB profile-file bound.

Normal startup installs this immutable selection through the existing recipient
port. Selection requires the authenticated append permission's exact tenant,
principal, and scope. The existing current resource grants remain authoritative
and are checked on each request. Caller-supplied descriptors do not choose keys
or readers. A successor profile requires restarting the host to change custody;
retained attachment bytes and historical reader keys remain separate.
