use utoipa::openapi::tag::TagBuilder;
use utoipa::openapi::{InfoBuilder, LicenseBuilder, OpenApi, OpenApiBuilder, ServerBuilder};

use serde_json::json;
use trellis_service_client::{
    ACCEPTED_ATTACHMENT_EVENT_TYPE_LITERAL, COMPLETION_EVENT, SubstrateAppendBody,
};
use utoipa::PartialSchema;

use crate::adapters::{AdmissionRouter, EventTypeCatalog};

/// Adds the append vocabulary from the registered event specifications.
pub(crate) fn append_schema(
    catalog: &EventTypeCatalog,
    admission: &AdmissionRouter,
) -> serde_json::Map<String, serde_json::Value> {
    let mut schema =
        serde_json::to_value(SubstrateAppendBody::schema()).expect("append body schema serializes");
    let literals: Vec<_> = catalog
        .entries()
        .filter(|entry| {
            !matches!(
                entry.event_type.as_str(),
                COMPLETION_EVENT | ACCEPTED_ATTACHMENT_EVENT_TYPE_LITERAL
            )
        })
        .map(|entry| entry.event_type.as_str())
        .collect();
    schema["properties"]["eventType"]["enum"] = serde_json::json!(literals);
    let mut schemas = serde_json::Map::new();
    let contract_events: Vec<_> = catalog
        .entries()
        .filter(|entry| admission.is_contract_event(&entry.event_type))
        .collect();
    if !contract_events.is_empty() {
        let event_types: Vec<_> = contract_events
            .iter()
            .map(|entry| &entry.event_type)
            .collect();
        let mut constraints = vec![json!({
            "if": { "required": ["expectedTreeSize"] },
            "then": { "properties": { "eventType": { "enum": event_types } } }
        })];
        constraints.extend(contract_events.into_iter().map(|entry| {
            json!({
                "if": {
                    "properties": { "eventType": { "const": entry.event_type } },
                    "required": ["eventType"]
                },
                "then": { "properties": { "payload": { "$ref": entry.schema_ref.as_str() } } }
            })
        }));
        schema["allOf"] = json!([{ "$ref": "#/components/schemas/ContractAppendConstraints" }]);
        schemas.insert(
            "ContractAppendConstraints".to_owned(),
            json!({ "allOf": constraints }),
        );
    }
    schemas.insert("SubstrateAppendBody".to_owned(), schema);
    schemas
}

/// The document skeleton every route declaration is added to.
pub(crate) fn base_document() -> OpenApi {
    OpenApiBuilder::new()
        .info(
            InfoBuilder::new()
                .title("Trellis Substrate API")
                .version("1.0.0")
                .description(Some("HTTP boundary for appending events, reading Core exports assembled on request, and retrieving registry projections from the Trellis substrate service."))
                .license(Some(LicenseBuilder::new().name("Apache-2.0").build()))
                .build(),
        )
        .servers(Some([ServerBuilder::new()
            .url("/")
            .description(Some("Trellis service root."))
            .build()]))
        .tags(Some([
            TagBuilder::new().name("events").description(Some("Append proof-bearing events into a Trellis scope.")).build(),
            TagBuilder::new().name("bundles").description(Some("Read Trellis export bundles by scope and checkpoint.")).build(),
            TagBuilder::new().name("registries").description(Some("Read registry snapshots bound into Trellis bundles.")).build(),
        ]))
        .build()
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[test]
    fn openapi_append_contract_matches_json_schema() {
        let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../specs/trellis-http-api.schema.json");
        let schema: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(schema_path).expect("schema file")).unwrap();
        let openapi = serde_json::to_value(crate::tests::documents_of_test_state().stack).unwrap();
        let schema_events = schema["$defs"]["EventType"]["enum"]
            .as_array()
            .expect("schema EventType enum");
        let append_body_schema = &openapi["components"]["schemas"]["SubstrateAppendBody"];
        assert!(
            append_body_schema["properties"].get("eventType").is_some(),
            "OpenAPI SubstrateAppendBody must declare eventType"
        );
        let openapi_enum = append_body_schema["properties"]["eventType"]["enum"]
            .as_array()
            .expect("OpenAPI eventType must be a string enum (TWREF-094)");
        let openapi_sorted = {
            let mut v: Vec<String> = openapi_enum
                .iter()
                .map(|x| x.as_str().expect("event type literal").to_string())
                .collect();
            v.sort();
            v
        };
        let schema_sorted = {
            let mut v: Vec<String> = schema_events
                .iter()
                .map(|x| x.as_str().expect("event type literal").to_string())
                .collect();
            v.sort();
            v
        };
        assert_eq!(
            openapi_sorted, schema_sorted,
            "OpenAPI eventType enum must match trellis-http-api.schema.json EventType"
        );
    }

    #[test]
    fn openapi_registry_declares_trellis_append_response_shape() {
        let doc = serde_json::to_value(crate::tests::documents_of_test_state().stack).unwrap();
        let schemas = doc["components"]["schemas"].as_object().unwrap();
        let append_properties = schemas["SubstrateAppendResult"]["properties"]
            .as_object()
            .unwrap();
        for property in [
            "eventId",
            "sequence",
            "priorEventHash",
            "canonicalEventHash",
            "checkpointRef",
        ] {
            assert!(
                append_properties.contains_key(property),
                "SubstrateAppendResult must expose {property}"
            );
        }
        for removed in ["bundleRef", "verificationReceipt"] {
            assert!(
                !append_properties.contains_key(removed),
                "SubstrateAppendResult no longer carries {removed}: nothing is published at append"
            );
        }
        assert!(schemas.get("VerificationReceipt").is_none());
    }

    #[test]
    fn openapi_append_route_declares_problem_json_error_responses() {
        let doc = serde_json::to_value(crate::tests::documents_of_test_state().stack).unwrap();
        let responses = doc["paths"]["/v1/scopes/{scope}/events"]["post"]["responses"]
            .as_object()
            .expect("appendEvent responses");
        assert!(responses.contains_key("201"));
        for status in ["400", "401", "403", "409", "413", "415", "422", "503"] {
            let entry = responses
                .get(status)
                .unwrap_or_else(|| panic!("appendEvent missing status {status} in OpenAPI"));
            assert_eq!(
                entry["content"]["application/problem+json"]["schema"]["$ref"],
                "#/components/schemas/Problem",
                "appendEvent status {status} must reference Problem JSON"
            );
        }
    }
}
