# Manual completion and retained HTML

The completion trigger identifies the expected ledger head and every formal signing event. The selected owning service supplies the complete case evidence and verifies current permission to disclose it. The default server has no selected completion provider and refuses the operation.

`trellis-cli seal-completion <client-config.json> <scope> <request.json>` reads this closed client configuration:

```json
{
  "endpoint": "http://127.0.0.1:18198",
  "tenant": {
    "tenant": "example",
    "workspace": "example",
    "environment": "development",
    "cell": "example"
  },
  "bearerTokenFile": "/private/path/service-token",
  "callerBearerTokenFile": "/private/path/person-token"
}
```

Each token file contains its raw bearer token. The client sends the service token through `Authorization` and the optional person token through `x-stack-completion-caller-authorization`. The selected WOS provider must verify both identities and current case and field permissions; a supplied token does not establish permission. Neither token enters the trigger body or certificate. Keep token files outside source control.

`trellis-cli verify-export <bundle.zip> [--certificate-authorities <registry.json>]` verifies the exported archive. Selecting a registry independently establishes the operator authority checks; the default reports that authority as unchecked.

The selected local demonstration authority is `urn:formspec:demo:d1:completion-authority:local`, with class `new`, a separate Ed25519 key, and a finite 30-day interval. Its public registry permits only `trellis.certificate-of-completion.v2`. Verification with this registry establishes fictional local demo trust and provides no official agency trust. The operator configuration remains inactive until the owning WOS route, current permissions, and complete case export qualify.

`trellis-cli certificate <bundle.zip> --certificate-id <id> --out <new-file.html> [--certificate-authorities <registry.json>]` verifies the archive and extracts the exact retained HTML for the selected certificate. It refuses an existing output file.

The committed v2 fixtures use public test keys and controlled signing records. They establish byte and protocol behavior. Qualification of the actual WOS adapter, current person permissions, complete Source evidence, and PostgreSQL restart behavior remains separate.
