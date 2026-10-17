use utoipa::openapi::tag::TagBuilder;
use utoipa::openapi::{InfoBuilder, LicenseBuilder, OpenApi, OpenApiBuilder, ServerBuilder};

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

    use wos_events::{WOS_CANONICAL_EVENT_LITERALS, WOS_NATIVE_PROVENANCE_EVENT_LITERAL};

    use crate::test_adapters::{
        FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH, FORMSPEC_RESPONSE_SUBMITTED,
    };

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
        for event_type in schema_events {
            let literal = event_type.as_str().expect("event type literal");
            assert!(
                WOS_CANONICAL_EVENT_LITERALS.contains(&literal)
                    || literal == WOS_NATIVE_PROVENANCE_EVENT_LITERAL
                    || literal == FORMSPEC_RESPONSE_SUBMITTED
                    || literal == FORMSPEC_RESPONSE_ACTION_SESSION_OP_BATCH,
                "schema EventType enum must only list admitted server literals"
            );
        }
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
}
