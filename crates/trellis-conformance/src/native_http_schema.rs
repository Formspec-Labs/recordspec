//! Offline HTTP-schema validation with the owning native schema resource.

use referencing::{Registry, Resource};
use serde_json::{Value, json};
use std::path::Path;

#[test]
fn native_provenance_http_schema_resolves_owning_resource_offline() {
    let package = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml")).unwrap();
    let owner = package.join(
        manifest["dev-dependencies"]["wos-events"]["path"]
            .as_str()
            .unwrap(),
    );
    let native_path = owner
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("schemas/wos-native-provenance-event.schema.json");
    let native: Value = serde_json::from_slice(&std::fs::read(native_path).unwrap()).unwrap();
    let uri = native["$id"].as_str().unwrap().to_owned();
    let registry = Registry::new()
        .add(uri, Resource::from_contents(native))
        .unwrap()
        .prepare()
        .unwrap();
    let http: Value =
        serde_json::from_str(include_str!("../../../specs/trellis-http-api.schema.json")).unwrap();
    let validator = jsonschema::options()
        .with_registry(&registry)
        .should_validate_formats(true)
        .build(&http)
        .unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/native-provenance-routing.json"
    ))
    .unwrap();
    let mut body = json!({
        "eventType": fixture["eventType"], "idempotencyKey": "native-schema",
        "actor": {"kind":"service", "subject":"wos-server"},
        "payload": fixture["payload"],
        "computeContext": {"declarationId":"compute:wos-server:publicMetadata", "actor":"wos-server", "sensitivity":"publicMetadata"}
    });
    assert!(validator.is_valid(&body));
    let original = body.clone();
    for kind in ["unknownFutureKind", "caseCreated"] {
        body["payload"]["record"]["recordKind"] = json!(kind);
        assert!(!validator.is_valid(&body));
    }
    body = original.clone();
    body["payload"]["record"]
        .as_object_mut()
        .unwrap()
        .remove("recordKind");
    assert!(!validator.is_valid(&body));
    body = original;
    body["payload"]["record"]["unrecognizedStructuralField"] = json!("refuse");
    assert!(!validator.is_valid(&body));
}
