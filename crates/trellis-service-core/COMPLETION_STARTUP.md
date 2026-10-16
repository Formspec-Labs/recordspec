# Completion startup

The normal server first loads its required incoming OIDC profile and current resource grants. Completion is optional and uses two additional private files:

- `TRELLIS_COMPLETION_CONFIG_FILE`: the independently registered outgoing client of the owning service.
- `TRELLIS_COMPLETION_OPERATOR_CONFIG_FILE`: explicitly selected completion operator keys.

Both absent leaves completion unselected. One missing or empty file setting fails startup. Both files are validated before ledger keys or database setup. Loading files does not register a client, grant owner permissions, or establish operator legitimacy.

The service profile is a closed JSON object:

```json
{
  "origin": "https://owner.example",
  "tenantHeaders": {
    "tenant": "x-owner-tenant-id",
    "workspace": "x-owner-workspace-id",
    "environment": "x-owner-environment-id",
    "cell": "x-owner-cell-id"
  },
  "tenantScope": {
    "tenant": "selected-tenant",
    "workspace": "selected-workspace",
    "environment": "selected-environment",
    "cell": "selected-cell"
  },
  "issuer": "https://issuer.example/realm",
  "audience": "selected-owner-audience",
  "requiredScopes": ["selected-completion-scope"],
  "allowedClients": ["selected-completion-client"],
  "profile": "keycloak",
  "allowDevelopmentLoopbackHttp": false,
  "clientId": "selected-completion-client",
  "scopes": ["selected-completion-scope"],
  "authentication": "clientSecretBasic",
  "assurance": "registeredClient",
  "clientSecretFile": "completion-client.secret"
}
```

`tenantHeaders` names the lowercase request headers the owning service reads its tenant tuple from; all four are required. `profile` accepts `keycloak`, `oktaCustomAuthorizationServer`, or `rfc9068`. `authentication` and `assurance` accept only the values shown. The development flag defaults to false. The origin must be a root HTTPS origin with no credentials, query, or fragment. Explicit development mode also allows literal loopback HTTP; hostnames such as `localhost` remain refused.

The tenant must equal the incoming OIDC deployment tuple and is checked again on every selection. `allowedClients` must contain exactly `clientId`. Requested and required scopes must be nonempty, unique, and equal as sets. The maintained `OidcClientCredentials` provider acquires and verifies the outgoing token. Incoming exporter credentials and borrowed person authorization serve separate purposes.

The operator file is a closed JSON array of one to eight objects. Each object requires `authority` (unique nonempty string), `authorityClass` (`prior` or `new`), `publicKey` (32-byte integer array), `validFrom` and `validUntil` (Unix seconds and nanoseconds pairs), and `coseKeyFile` (explicit private COSE key path). The existing signer checks the public/private key pair and finite increasing interval. Selection matches authority, class, and public key exactly. It never implicitly reuses the ledger event key.

Secret and COSE paths resolve relative to their containing configuration file; absolute paths are also accepted. Every file must be a private regular file owned by the current user, have no group/other permissions, and stay within one MiB. Final symlinks and nonregular files are refused. Secret trailing CR/LF is trimmed. Diagnostics contain no credentials or upstream response bodies.

The owning service remains responsible for current machine and person permissions, legal case association, complete evidence census, and exact archive-to-prefix verification. Successful configuration loading does not qualify those behaviors.
