// Actual maintained OIDC protocol and current resource-authority tests.
// Rust guideline compliant 2026-02-21
use super::*;
use crate::oidc_startup::StartupAuth;
use serde_json::{Value, json};
use stack_common_auth::{
    AccessTokenError,
    oidc::{AuthClock, AuthHttpClient, AuthHttpRequest, AuthHttpResponse, OidcDependencies},
};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

const ISSUER: &str = "https://issuer.example/realms/dev";
// Maintained stack-common public test fixture; never a deployment signing key.
const MODULUS: &str = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";

struct Clock;
impl AuthClock for Clock {
    fn unix_seconds(&self) -> i64 {
        10000
    }
}

struct ProtocolHttp {
    active: AtomicBool,
    introspections: AtomicUsize,
}
impl ProtocolHttp {
    fn new() -> Self {
        Self {
            active: AtomicBool::new(true),
            introspections: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl AuthHttpClient for ProtocolHttp {
    async fn send(&self, request: AuthHttpRequest) -> Result<AuthHttpResponse, AccessTokenError> {
        let value = if request.url == format!("{ISSUER}/.well-known/openid-configuration") {
            json!({"issuer":ISSUER,"authorization_endpoint":format!("{ISSUER}/authorize"),
                "token_endpoint":format!("{ISSUER}/token"),"jwks_uri":format!("{ISSUER}/keys"),
                "response_types_supported":["code"],"subject_types_supported":["public"],
                "id_token_signing_alg_values_supported":["RS256"]})
        } else if request.url == format!("{ISSUER}/keys") {
            json!({"keys":[{"kty":"RSA","n":MODULUS,"e":"AQAB","kid":"one","alg":"RS256","use":"sig","key_ops":["verify"]}]})
        } else if request.url == format!("{ISSUER}/introspect") {
            assert_eq!(request.method, axum::http::Method::POST);
            assert!(
                request
                    .headers
                    .contains_key(axum::http::header::AUTHORIZATION)
            );
            self.introspections.fetch_add(1, Ordering::SeqCst);
            // The introspection answer describes the token it was asked about.
            let form = String::from_utf8_lossy(&request.body).into_owned();
            let token = form.split('&').find_map(|pair| pair.strip_prefix("token=")).unwrap_or_default();
            let claims = token
                .split('.')
                .nth(1)
                .and_then(|segment| base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, segment).ok())
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .unwrap_or_else(claims);
            json!({"active":self.active.load(Ordering::SeqCst),"iss":ISSUER,"sub":claims["sub"],
                "client_id":claims["azp"],"exp":10600,"token_type":"Bearer",
                "aud":["trellis-api","trellis-introspection"],"scope":claims["scope"]})
        } else {
            return Err(AccessTokenError::unavailable());
        };
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        Ok(AuthHttpResponse {
            status: StatusCode::OK,
            headers,
            body: serde_json::to_vec(&value).unwrap(),
        })
    }
}

fn claims() -> Value {
    json!({"iss":ISSUER,"aud":["trellis-api","trellis-introspection"],"sub":"external-producer",
        "iat":10000,"exp":10600,"typ":"Bearer","azp":"trellis-producer",
        "scope":"trellis.access trellis.read trellis.append trellis.administer","jti":"test-token"})
}

fn sign(claims: &Value) -> String {
    let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
    header.kid = Some("one".into());
    header.typ = Some("JWT".into());
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
            "../../../../stack-common/crates/stack-common-auth/tests/fixtures/public-test-rsa.pem"
        ))
        .unwrap(),
    )
    .unwrap()
}

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Files {
    root: PathBuf,
    profile: Value,
    grants: Value,
}
impl Files {
    fn new() -> Self {
        let serial = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let fixture = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "trellis-oidc-{}-{serial}-{fixture}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let tenant = json!({"tenant":"tenant-a","workspace":"workspace-a","environment":"prod","cell":"cell-a"});
        let profile = json!({"issuer":ISSUER,"audience":"trellis-api","requiredScopes":["trellis.access"],
            "allowedClients":["trellis-producer"],"profile":"keycloak","introspectionEndpoint":format!("{ISSUER}/introspect"),
            "introspectionClientId":"trellis-introspection","introspectionClientSecretFile":"client.secret","grantsFile":"grants.json",
            "tenantScope":tenant,"identities":[{"issuer":ISSUER,"subject":"external-producer","clientId":"trellis-producer","principal":"internal-producer"}],
            "actionScopes":{"read":"trellis.read","append":"trellis.append","administer":"trellis.administer"}});
        let grants = json!({"tenantScope":tenant,"grants":[
            {"principal":"internal-producer","scope":"case_123","action":"append","actors":[{"kind":"service","subject":"wos-server"}],
                "payloadActors":[{"pointer":"/actorId","required":false,"subjects":["selected-human"]}]},
            {"principal":"internal-producer","scope":"case_123","action":"read"},
            {"principal":"internal-producer","scope":"case_123","action":"administer"}]});
        let file = Self {
            root,
            profile,
            grants,
        };
        file.write("client.secret", b"public-test-only-client-secret");
        file.save();
        file
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        let path = self.root.join(name);
        fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    fn save(&self) {
        self.write("profile.json", &serde_json::to_vec(&self.profile).unwrap());
        self.write("grants.json", &serde_json::to_vec(&self.grants).unwrap());
    }
    fn load(&self, http: Arc<ProtocolHttp>) -> Result<StartupAuth, stack_common_error::StackError> {
        StartupAuth::load(
            &self.root.join("profile.json"),
            OidcDependencies {
                http,
                clock: Arc::new(Clock),
            },
        )
    }
    fn app(&self, http: Arc<ProtocolHttp>) -> axum::Router {
        router(self.load(http).unwrap().apply(test_state())).unwrap()
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[tokio::test]
async fn oidc_startup_changed_actor_kind_grant_blocks_the_same_cached_body() {
    let mut files = Files::new();
    let app = files.app(Arc::new(ProtocolHttp::new()));
    let token = sign(&claims());
    let body = append_body("oidc-kind-retry");
    assert_eq!(
        app.clone()
            .oneshot(request(body.clone(), &token))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    files.grants["grants"][0]["actors"][0]["kind"] = json!("human");
    files.save();
    assert_eq!(
        app.oneshot(request(body, &token)).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn oidc_startup_required_payload_selector_refuses_missing_nontext_and_foreign_human() {
    let mut files = Files::new();
    files.grants["grants"][0]["payloadActors"][0]["required"] = json!(true);
    files.save();
    let app = files.app(Arc::new(ProtocolHttp::new()));
    let token = sign(&claims());
    for actor in [None, Some(json!(42)), Some(json!("foreign-human"))] {
        let mut body: Value = serde_json::from_slice(&append_body("oidc-required-human")).unwrap();
        if let Some(actor) = actor {
            body["payload"]["actorId"] = actor;
        }
        assert_eq!(
            app.clone()
                .oneshot(request(serde_json::to_vec(&body).unwrap(), &token))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
}

#[tokio::test]
async fn oidc_startup_retained_head_requires_current_read_without_administer() {
    let mut files = Files::new();
    let app = files.app(Arc::new(ProtocolHttp::new()));
    let token = sign(&claims());
    assert_eq!(
        app.clone()
            .oneshot(request(append_body("oidc-head"), &token))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    let head = || {
        let mut request = get_request("/v1/scopes/case_123/bundles/head");
        request
            .headers_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    };
    assert_eq!(
        app.clone().oneshot(head()).await.unwrap().status(),
        StatusCode::OK
    );
    files.grants["grants"]
        .as_array_mut()
        .unwrap()
        .retain(|grant| grant["action"] != "administer");
    files.save();
    assert_eq!(
        app.clone().oneshot(head()).await.unwrap().status(),
        StatusCode::OK
    );
    files.grants["grants"]
        .as_array_mut()
        .unwrap()
        .retain(|grant| grant["action"] != "read");
    files.save();
    assert_eq!(
        app.oneshot(head()).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

fn request(body: Vec<u8>, token: &str) -> Request<Body> {
    post_request_bearer("/v1/scopes/case_123/events", body, token)
}

#[tokio::test]
async fn oidc_startup_real_protocol_rechecks_token_and_current_case_grant_before_replay() {
    let mut files = Files::new();
    let http = Arc::new(ProtocolHttp::new());
    let app = files.app(http.clone());
    let token = sign(&claims());
    let body = append_body("oidc-retry");
    assert_eq!(
        app.clone()
            .oneshot(request(body.clone(), &token))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    files.grants["grants"] = json!([]);
    files.save();
    assert_eq!(
        app.clone()
            .oneshot(request(body.clone(), &token))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    http.active.store(false, Ordering::SeqCst);
    assert_eq!(
        app.oneshot(request(body, &token)).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(http.introspections.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn oidc_startup_protocol_refuses_wrong_issuer_audience_client_or_base_scope() {
    let files = Files::new();
    let app = files.app(Arc::new(ProtocolHttp::new()));
    for (field, value) in [
        ("iss", json!("https://foreign.example")),
        ("aud", json!(["other-api"])),
        ("azp", json!("foreign-client")),
        ("scope", json!("trellis.read")),
        ("exp", json!(9999)),
    ] {
        let mut wrong = claims();
        wrong[field] = value;
        assert_eq!(
            app.clone()
                .oneshot(request(append_body("oidc-token-reject"), &sign(&wrong)))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn oidc_startup_action_scope_is_required_beyond_base_oauth_access() {
    let files = Files::new();
    let app = files.app(Arc::new(ProtocolHttp::new()));
    let mut token = claims();
    token["scope"] = json!("trellis.access trellis.read");
    assert_eq!(
        app.oneshot(request(append_body("oidc-action-scope"), &sign(&token)))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn oidc_startup_refuses_foreign_tenant_component_scope_and_actor_kind() {
    let files = Files::new();
    let app = files.app(Arc::new(ProtocolHttp::new()));
    let token = sign(&claims());
    for name in [
        "x-wos-tenant-id",
        "x-wos-workspace-id",
        "x-wos-environment-id",
        "x-wos-cell-id",
    ] {
        let mut foreign = request(append_body("oidc-foreign-tuple"), &token);
        foreign
            .headers_mut()
            .insert(name, axum::http::HeaderValue::from_static("foreign"));
        assert_eq!(
            app.clone().oneshot(foreign).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    let mut foreign = request(append_body("oidc-foreign-case"), &token);
    *foreign.uri_mut() = "/v1/scopes/foreign_case/events".parse().unwrap();
    assert_eq!(
        app.clone().oneshot(foreign).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut body: Value = serde_json::from_slice(&append_body("oidc-wrong-kind")).unwrap();
    body["actor"]["kind"] = json!("human");
    assert_eq!(
        app.oneshot(request(serde_json::to_vec(&body).unwrap(), &token))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn oidc_startup_revoked_payload_delegation_blocks_unchanged_cached_retry() {
    let mut files = Files::new();
    let app = files.app(Arc::new(ProtocolHttp::new()));
    let token = sign(&claims());
    let mut body: Value = serde_json::from_slice(&append_body("oidc-delegation-retry")).unwrap();
    body["payload"]["actorId"] = json!("selected-human");
    let body = serde_json::to_vec(&body).unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request(body.clone(), &token))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    files.grants["grants"][0]["payloadActors"][0]["subjects"] = json!(["different-human"]);
    files.save();
    assert_eq!(
        app.oneshot(request(body, &token)).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn a_prefix_grant_admits_its_scopes_and_refuses_others() {
    let mut files = Files::new();
    files.grants["grants"] = json!([{"principal":"internal-producer","scopePrefix":"keya.",
        "action":"append","actors":[{"kind":"service","subject":"wos-server"}]}]);
    files.save();
    let app = files.app(Arc::new(ProtocolHttp::new()));
    let token = sign(&claims());
    let append = |scope: &str| {
        post_request_bearer(
            &format!("/v1/scopes/{scope}/events"),
            append_body("oidc-prefix"),
            &token,
        )
    };
    for (scope, expected) in [
        ("keya.case_1", StatusCode::CREATED),
        ("keya.case_2", StatusCode::CREATED),
        ("keyb.case_1", StatusCode::FORBIDDEN),
        ("keya", StatusCode::FORBIDDEN),
        ("keyab.case_1", StatusCode::FORBIDDEN),
    ] {
        assert_eq!(
            app.clone().oneshot(append(scope)).await.unwrap().status(),
            expected,
            "{scope}"
        );
    }
}

#[test]
fn oidc_startup_closed_profile_and_current_grant_validation_refuse_ambiguous_authority() {
    let mut files = Files::new();
    let original = files.grants.clone();
    for mutation in 0..9 {
        files.grants = original.clone();
        match mutation {
            0 => files.grants["tenantScope"]["workspace"] = json!("foreign"),
            1 => files.grants["grants"][0]["principal"] = json!("unmapped"),
            2 => {
                let row = files.grants["grants"][0].clone();
                files.grants["grants"].as_array_mut().unwrap().push(row);
            }
            3 => files.grants["grants"][0]["payloadActors"][0]["pointer"] = json!("/bad~escape"),
            4 => {
                files.grants["grants"][1]["actors"] =
                    json!([{"kind":"service","subject":"wos-server"}])
            }
            5 => {
                files.grants["grants"][0]["payloadActors"][0]["subjects"] =
                    json!(["duplicate", "duplicate"])
            }
            6 => files.grants["grants"][0]["scopePrefix"] = json!("key."),
            7 => {
                files.grants["grants"][1]["scopePrefix"] = json!("key");
                files.grants["grants"][1].as_object_mut().unwrap().remove("scope");
            }
            _ => files.grants["unknown"] = json!(true),
        }
        files.save();
        assert!(files.load(Arc::new(ProtocolHttp::new())).is_err());
    }
    files.grants = original;
    let duplicate = files.profile["identities"][0].clone();
    files.profile["identities"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    files.save();
    assert!(files.load(Arc::new(ProtocolHttp::new())).is_err());
}

#[tokio::test]
async fn oidc_startup_unavailable_or_invalid_current_grants_fail_closed_after_admission() {
    let files = Files::new();
    let app = files.app(Arc::new(ProtocolHttp::new()));
    let token = sign(&claims());
    files.write("grants.json", b"{invalid");
    assert_eq!(
        app.clone()
            .oneshot(request(append_body("oidc-invalid-grants"), &token))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    fs::remove_file(files.root.join("grants.json")).unwrap();
    assert_eq!(
        app.oneshot(request(append_body("oidc-missing-grants"), &token))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn oidc_startup_rejects_duplicate_fields_in_profile_and_grants() {
    let files = Files::new();
    let grants = serde_json::to_string(&files.grants).unwrap();
    let duplicate = grants.replacen(
        "{",
        &format!("{{\"tenantScope\":{},", files.grants["tenantScope"]),
        1,
    );
    files.write("grants.json", duplicate.as_bytes());
    assert!(files.load(Arc::new(ProtocolHttp::new())).is_err());
    files.save();
    let profile = serde_json::to_string(&files.profile).unwrap();
    let duplicate = profile.replacen(
        "{",
        &format!("{{\"issuer\":{},", files.profile["issuer"]),
        1,
    );
    files.write("profile.json", duplicate.as_bytes());
    assert!(files.load(Arc::new(ProtocolHttp::new())).is_err());
}

#[cfg(unix)]
#[test]
fn oidc_startup_private_files_reject_shared_permissions_and_symlinks() {
    use std::os::unix::{fs::PermissionsExt, fs::symlink};
    let files = Files::new();
    fs::set_permissions(
        files.root.join("client.secret"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(files.load(Arc::new(ProtocolHttp::new())).is_err());
    files.write("client.secret", b"public-test-only-client-secret");
    fs::rename(
        files.root.join("grants.json"),
        files.root.join("other.json"),
    )
    .unwrap();
    symlink(Path::new("other.json"), files.root.join("grants.json")).unwrap();
    assert!(files.load(Arc::new(ProtocolHttp::new())).is_err());
}

fn attachment_selection() -> Value {
    // Public maintained vector key, without deployment custody assertions.
    json!([{"principal":"internal-producer","scope":"case_123","recipients":[{
        "id":"fixture-reader-v1",
        "publicKey":hex::decode("7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13").unwrap(),
        "operatorHeld":false
    }]}])
}

fn attachment_descriptor()
-> trellis_admission_formspec::accepted_attachment::AcceptedAttachmentDescriptor {
    serde_json::from_value(json!({
        "version":1,"responseId":"fixture-response","responseHash":format!("sha256:{}", "00".repeat(32)),
        "sourceId":"urn:fixture:source","serviceBindingId":"fixture-binding",
        "acceptedActorRef":"actor:human:fixture","formId":"fixture-form","subjectRef":"fixture-subject",
        "fieldPath":"/file","uploadId":"fixture-upload","acceptedAttachmentId":"fixture-occurrence",
        "bindingAttachmentId":"fixture-slot","mediaType":"application/octet-stream","byteLength":1,
        "attachmentSha256":format!("sha256:{}", "00".repeat(32)),"objectUri":"urn:fixture:object", "filename":null, "priorBindingHash":null
    })).unwrap()
}

#[tokio::test]
async fn oidc_startup_composes_selected_attachment_recipients() {
    let mut files = Files::new();
    files.profile["acceptedAttachmentRecipients"] = attachment_selection();
    files.save();
    let state = files
        .load(Arc::new(ProtocolHttp::new()))
        .unwrap()
        .apply(test_state());
    let selector = state
        .external_attachment_recipients
        .as_ref()
        .expect("normal startup installs selection");
    let permit = trellis_server_ports::AuthorizedScope {
        principal: "internal-producer".into(),
        tenant_scope: serde_json::from_value(files.profile["tenantScope"].clone()).unwrap(),
        scope: b"case_123".to_vec(),
        action: trellis_server_ports::ScopeAction::Append,
    };
    let recipients = selector
        .select(&permit, &serde_json::to_value(attachment_descriptor()).unwrap())
        .await
        .unwrap();
    assert_eq!(recipients.len(), 1);
    assert_eq!(recipients[0].id, b"fixture-reader-v1");
    assert!(!recipients[0].operator_held);
}

#[test]
fn oidc_startup_attachment_selection_is_optional_and_fails_closed_when_selected() {
    let files = Files::new();
    assert!(
        files
            .load(Arc::new(ProtocolHttp::new()))
            .unwrap()
            .apply(test_state())
            .external_attachment_recipients
            .is_none()
    );
    let selected = attachment_selection();
    let mut invalid = vec![
        json!(null),
        json!([]),
        json!([selected[0].clone(), selected[0].clone()]),
    ];
    for (path, value) in [
        ("/0/principal", json!("unknown-principal")),
        ("/0/scope", json!("bad/scope")),
        ("/0/recipients", json!([])),
        ("/0/recipients/0/id", json!("")),
        ("/0/recipients/0/id", json!(" ")),
        ("/0/recipients/0/id", json!("reader\n")),
        ("/0/recipients/0/id", json!("x".repeat(257))),
        ("/0/recipients/0/publicKey", json!(vec![0u8; 32])),
        ("/0/recipients/0/publicKey", json!(vec![1u8; 31])),
        ("/0/recipients/0/operatorHeld", json!(true)),
    ] {
        let mut selection = selected.clone();
        *selection.pointer_mut(path).unwrap() = value;
        invalid.push(selection);
    }
    let mut duplicate_id = selected.clone();
    let mut second = selected[0]["recipients"][0].clone();
    second["publicKey"][0] = json!(18);
    duplicate_id[0]["recipients"]
        .as_array_mut()
        .unwrap()
        .push(second);
    invalid.push(duplicate_id);
    let mut duplicate_key = selected.clone();
    let mut second = selected[0]["recipients"][0].clone();
    second["id"] = json!("another-reader");
    duplicate_key[0]["recipients"]
        .as_array_mut()
        .unwrap()
        .push(second);
    invalid.push(duplicate_key);
    let mut unknown_field = selected.clone();
    unknown_field[0]["recipients"][0]["callerKey"] = json!(true);
    invalid.push(unknown_field);
    let oversized_rows = (0..1025)
        .map(|index| {
            let mut row = selected[0].clone();
            row["scope"] = json!(format!("case_{index}"));
            row
        })
        .collect::<Vec<_>>();
    invalid.push(json!(oversized_rows));
    let mut oversized_recipients = selected.clone();
    oversized_recipients[0]["recipients"] = json!(
        (0..65)
            .map(|index| {
                let mut recipient = selected[0]["recipients"][0].clone();
                recipient["id"] = json!(format!("fixture-reader-{index}"));
                recipient["publicKey"][0] = json!(index);
                recipient
            })
            .collect::<Vec<_>>()
    );
    invalid.push(oversized_recipients);
    for selection in invalid {
        let mut files = Files::new();
        files.profile["acceptedAttachmentRecipients"] = selection;
        files.save();
        let error = files
            .load(Arc::new(ProtocolHttp::new()))
            .err()
            .expect("invalid selection must refuse startup");
        assert!(
            error
                .to_string()
                .contains("accepted-attachment recipient selection invalid"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn oidc_startup_attachment_selection_requires_exact_admitted_append_permission() {
    let mut files = Files::new();
    files.profile["acceptedAttachmentRecipients"] = attachment_selection();
    files.save();
    let state = files
        .load(Arc::new(ProtocolHttp::new()))
        .unwrap()
        .apply(test_state());
    let selector = state.external_attachment_recipients.as_ref().unwrap();
    let allowed = trellis_server_ports::AuthorizedScope {
        principal: "internal-producer".into(),
        tenant_scope: serde_json::from_value(files.profile["tenantScope"].clone()).unwrap(),
        scope: b"case_123".to_vec(),
        action: trellis_server_ports::ScopeAction::Append,
    };
    for changed in 0..4 {
        let mut permit = allowed.clone();
        match changed {
            0 => permit.principal = "unknown-principal".into(),
            1 => permit.scope = b"case_124".to_vec(),
            2 => permit.tenant_scope.tenant = "other-tenant".into(),
            _ => permit.action = trellis_server_ports::ScopeAction::Read,
        }
        let error = selector
            .select(&permit, &serde_json::to_value(attachment_descriptor()).unwrap())
            .await
            .err()
            .expect("mismatched permission refused");
        assert!(
            error
                .to_string()
                .contains("accepted-attachment recipient selection required"),
            "{error}"
        );
    }
}

// ---- the completion seal through the shipped OIDC and grant path ------------------------------

/// A seal server whose callers are told apart by their real tokens and current grants:
/// the configured publisher, a case writer who may append and read but is not the publisher,
/// and callers holding only one of the two actions.
async fn seal_server() -> (axum::Router, Arc<super::completion_tests::Signer>, Files, trellis_service_client::CompletionRequest) {
    let mut files = Files::new();
    let callers = [
        // (subject, principal, actions)
        ("case-writer", "case-writer", vec!["append", "read"]),
        ("append-only", "append-only", vec!["append"]),
        ("read-only", "read-only", vec!["read"]),
    ];
    let mut grants = vec![json!({"principal":"internal-producer","scope":"case_completion","action":"append","actors":[{"kind":"service","subject":"external-producer"}]}),
        json!({"principal":"internal-producer","scope":"case_completion","action":"read"})];
    for (subject, principal, actions) in callers {
        files.profile["identities"].as_array_mut().unwrap().push(
            json!({"issuer":ISSUER,"subject":subject,"clientId":"trellis-producer","principal":principal}));
        for action in actions {
            let mut grant = json!({"principal":principal,"scope":"case_completion","action":action});
            if action == "append" {
                grant["actors"] = json!([{"kind":"service","subject":subject}]);
            }
            grants.push(grant);
        }
    }
    files.grants["grants"].as_array_mut().unwrap().extend(grants);
    files.save();
    let signer = Arc::new(super::completion_tests::Signer { calls: AtomicUsize::new(0), corrupt: false });
    // The publisher is the principal the profile maps the WOS machine client to.
    let state = files
        .load(Arc::new(ProtocolHttp::new()))
        .unwrap()
        .apply(test_state())
        .with_completion(signer.clone(), "internal-producer");
    let (state, _, _, request) = super::completion_tests::fixture_on(state).await;
    (router(state).unwrap(), signer, files, request)
}

fn seal_request(request: &trellis_service_client::CompletionRequest, token: Option<&str>) -> Request<Body> {
    let path = "/v1/scopes/case_completion/completion";
    let body = serde_json::to_vec(request).unwrap();
    match token {
        Some(token) => post_request_bearer(path, body, token),
        None => Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(IDEMPOTENCY_KEY_HEADER, &request.idempotency_key)
            .header("x-wos-tenant-id", "tenant-a")
            .header("x-wos-workspace-id", "workspace-a")
            .header("x-wos-environment-id", "prod")
            .header("x-wos-cell-id", "cell-a")
            .body(Body::from(body))
            .unwrap(),
    }
}
fn token_for(subject: &str) -> String {
    let mut claims = claims();
    claims["sub"] = json!(subject);
    sign(&claims)
}
async fn answer(app: &axum::Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    let title = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|body| body["title"].as_str().map(str::to_owned))
        .unwrap_or_default();
    (status, title)
}

#[tokio::test]
async fn seal_refuses_a_case_writer_who_is_not_the_publisher() {
    let (app, signer, _files, request) = seal_server().await;
    let (status, title) = answer(&app, seal_request(&request, Some(&token_for("case-writer")))).await;
    assert_eq!(
        (status, title.as_str()),
        (StatusCode::FORBIDDEN, "completion seal requires the configured publisher"),
        "its own title, not a generic grant refusal"
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0, "the operator key signed nothing");
    // Nothing was reserved: the publisher seals the very same request.
    let (status, _) = answer(&app, seal_request(&request, Some(&token_for("external-producer")))).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn seal_without_a_token_is_unauthorized() {
    let (app, signer, _files, request) = seal_server().await;
    let (status, _) = answer(&app, seal_request(&request, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn seal_refuses_a_caller_missing_the_append_or_the_read_grant() {
    let (app, signer, _files, request) = seal_server().await;
    for subject in ["append-only", "read-only"] {
        let (status, title) = answer(&app, seal_request(&request, Some(&token_for(subject)))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{subject}");
        assert_ne!(title, "completion seal requires the configured publisher", "{subject}: refused earlier, by the grant");
    }
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
}
