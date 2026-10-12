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
            json!({"active":self.active.load(Ordering::SeqCst),"iss":ISSUER,"sub":"external-producer",
                "client_id":"trellis-producer","exp":10600,"token_type":"Bearer",
                "aud":["trellis-api","trellis-introspection"],"scope":"trellis.access trellis.read trellis.append trellis.administer"})
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
async fn oidc_startup_head_requires_current_read_and_administer_grants() {
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

#[test]
fn oidc_startup_closed_profile_and_current_grant_validation_refuse_ambiguous_authority() {
    let mut files = Files::new();
    let original = files.grants.clone();
    for mutation in 0..7 {
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
