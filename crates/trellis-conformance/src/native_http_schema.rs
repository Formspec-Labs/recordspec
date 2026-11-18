//! Offline validation against the HTTP schema and its payload schema resources.

use referencing::{Registry, Resource};
use serde_json::{Value, json};
use std::path::Path;

fn append_validator() -> jsonschema::Validator {
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
    let authority: Value =
        serde_json::from_str(include_str!("../../../specs/authority-events.schema.json")).unwrap();
    let authority_uri = authority["$id"].as_str().unwrap().to_owned();
    let openapi: Value =
        serde_json::from_str(include_str!("../../../specs/trellis-server.openapi.json")).unwrap();
    let registry = Registry::new()
        .add(
            "https://specs.formspec.dev/trellis/trellis-server.openapi.json",
            Resource::from_contents(openapi),
        )
        .unwrap()
        .add(uri, Resource::from_contents(native))
        .unwrap()
        .add(authority_uri, Resource::from_contents(authority))
        .unwrap()
        .prepare()
        .unwrap();
    let http: Value =
        serde_json::from_str(include_str!("../../../specs/trellis-http-api.schema.json")).unwrap();
    jsonschema::options()
        .with_registry(&registry)
        .should_validate_formats(true)
        .build(&http)
        .unwrap()
}

#[test]
fn native_provenance_http_schema_resolves_owning_resource_offline() {
    let validator = append_validator();
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
    body["expectedTreeSize"] = json!(0);
    assert!(!validator.is_valid(&body));
    body.as_object_mut().unwrap().remove("expectedTreeSize");
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

#[test]
fn authority_append_payloads_follow_the_authored_schema() {
    let validator = append_validator();
    let cases: Vec<Value> = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/authority-events.json"
    ))
    .unwrap();
    for case in cases {
        let mut body = json!({
            "eventType": case["eventType"],
            "idempotencyKey": "authority-schema",
            "actor": {"kind":"service", "subject":"producer"},
            "payload": case["payload"],
            "computeContext": {"declarationId":"compute:producer:publicMetadata",
                "actor":"producer", "sensitivity":"publicMetadata"}
        });
        assert!(validator.is_valid(&body), "{body}");
        body["expectedTreeSize"] = json!(0);
        assert!(validator.is_valid(&body), "{body}");
        for invalid in [json!(-1), json!(null), json!("1")] {
            body["expectedTreeSize"] = invalid;
            assert!(!validator.is_valid(&body), "{body}");
        }
        body.as_object_mut().unwrap().remove("expectedTreeSize");
        for contract in [
            "wos",
            "formspec",
            "genesis",
            "decisions",
            "decisions-9",
            "decisionsx",
            "a1234567890123456789012345678901",
        ] {
            body["payload"]["contract"] = json!(contract);
            assert!(validator.is_valid(&body), "{body}");
        }
        for invalid in ["", "Sample", "0sample", "bad_id", &"a".repeat(33)] {
            body["payload"]["contract"] = json!(invalid);
            assert!(!validator.is_valid(&body), "{body}");
        }
        body["payload"]["contract"] = case["payload"]["contract"].clone();
        body["payload"]["unknown"] = json!(true);
        assert!(!validator.is_valid(&body), "{body}");
    }
}
