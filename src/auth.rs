use axum::{
    extract::{Query, State},
    http::{header, HeaderMap},
    response::{Html, IntoResponse, Redirect, Response},
};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    reqwest::async_http_client,
    AuthenticationFlow, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;

const ZITADEL_ISSUER: &str = "https://docdockgo-kgfmnj.eu1.zitadel.cloud";
const CLIENT_ID: &str = "365975639251042712";
const REDIRECT_URI: &str = "http://localhost:3000/callback";
const POST_LOGOUT_REDIRECT_URI: &str = "http://localhost:3000/logged-out";

#[derive(Clone, Default)]
pub struct OidcState {
    pub pkce_verifier: Arc<Mutex<Option<String>>>,
    pub nonce: Arc<Mutex<Option<String>>>,
}

pub async fn build_oidc_client() -> CoreClient {
    let issuer_url = IssuerUrl::new(ZITADEL_ISSUER.to_string()).expect("Issuer URL invalide");
    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, async_http_client)
        .await
        .expect("Echec de la decouverte OIDC Zitadel");
    CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(CLIENT_ID.to_string()),
        None,
    )
    .set_redirect_uri(RedirectUrl::new(REDIRECT_URI.to_string()).expect("Redirect URI invalide"))
}

pub async fn login_handler(State(oidc_state): State<OidcState>) -> impl IntoResponse {
    let client = build_oidc_client().await;
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let nonce = Nonce::new_random();
    *oidc_state.pkce_verifier.lock().await = Some(pkce_verifier.secret().clone());
    *oidc_state.nonce.lock().await = Some(nonce.secret().clone());
    let (auth_url, _csrf_token, _nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            || nonce,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();
    Redirect::to(auth_url.as_str())
}

#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
struct ZitadelClaims {
    sub: String,
    #[serde(rename = "role")]
    role: Option<String>,
    #[serde(rename = "urn:zitadel:iam:org:project:roles")]
    zitadel_roles: Option<serde_json::Value>,
}

pub async fn callback_handler(
    State(oidc_state): State<OidcState>,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    let client = build_oidc_client().await;

    let verifier_secret = match oidc_state.pkce_verifier.lock().await.take() {
        Some(v) => v,
        None => {
            eprintln!("[AUTH] pkce_verifier manquant");
            return Redirect::to("/").into_response();
        }
    };

    let token_response = match client
        .exchange_code(AuthorizationCode::new(params.code))
        .set_pkce_verifier(PkceCodeVerifier::new(verifier_secret))
        .request_async(async_http_client)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[AUTH] Echec echange code : {:?}", e);
            return Redirect::to("/").into_response();
        }
    };

    let id_token = match token_response.id_token() {
        Some(t) => t,
        None => {
            eprintln!("[AUTH] ID token absent");
            return Redirect::to("/").into_response();
        }
    };

    // Garder le JWT brut pour le passer à end_session lors du logout
    let id_token_raw = id_token.to_string();

    let claims_str = match decode_jwt_payload(&id_token_raw) {
        Some(s) => s,
        None => {
            eprintln!("[AUTH] Impossible de décoder le JWT");
            return Redirect::to("/").into_response();
        }
    };

    // ⚠️ LOG TEMPORAIRE
    //println!("[AUTH] Claims bruts : {}", claims_str);

    let claims: ZitadelClaims = match serde_json::from_str(&claims_str) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[AUTH] Deserialisation claims echouee : {}", e);
            return Redirect::to("/").into_response();
        }
    };

    //println!("[AUTH] User connecte sub={}", claims.sub);

    let role = match determine_role(&claims) {
        Some(r) => r,
        None => {
            eprintln!("[AUTH] Aucun role trouve pour sub={}", claims.sub);
            return Redirect::to("/").into_response();
        }
    };

    //println!("[AUTH] Role attribue : {}", role);

    let mut headers = HeaderMap::new();

    // Cookie rôle (8h)
    headers.append(
        header::SET_COOKIE,
        format!("role={}; HttpOnly; Path=/; SameSite=Lax; Max-Age=28800", role)
            .parse()
            .unwrap(),
    );

    // Cookie id_token pour le logout (même durée que le rôle)
    // Le JWT ne contient que base64url + points, safe dans un cookie
    headers.append(
        header::SET_COOKIE,
        format!(
            "id_token={}; HttpOnly; Path=/; SameSite=Lax; Max-Age=28800",
            id_token_raw
        )
        .parse()
        .unwrap(),
    );

    (headers, Redirect::to(&format!("/dashboard/{}", role))).into_response()
}

// GET /logout
// Lit l'id_token depuis le cookie, supprime les deux cookies,
// puis redirige vers end_session Zitadel avec id_token_hint.
// Sans id_token_hint, Zitadel affiche une page de confirmation
// et ne détruit pas forcément la session → reconnexion automatique.
pub async fn logout(headers: HeaderMap) -> Response {
    let id_token_hint = extract_cookie(&headers, "id_token").unwrap_or_default();

    let mut resp_headers = HeaderMap::new();

    resp_headers.append(
        header::SET_COOKIE,
        "role=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
            .parse()
            .unwrap(),
    );
    resp_headers.append(
        header::SET_COOKIE,
        "id_token=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
            .parse()
            .unwrap(),
    );

    let end_session_url = if id_token_hint.is_empty() {
        // Cookie absent (déjà expiré ?) → logout local uniquement
        println!("[AUTH] logout sans id_token_hint");
        "/logged-out".to_string()
    } else {
        println!("[AUTH] logout avec id_token_hint → end_session Zitadel");
        format!(
            "{}/oidc/v1/end_session?id_token_hint={}&post_logout_redirect_uri={}",
            ZITADEL_ISSUER, id_token_hint, POST_LOGOUT_REDIRECT_URI
        )
    };

    (resp_headers, Redirect::to(&end_session_url)).into_response()
}

// GET /logged-out — Zitadel redirige ici après destruction de la session SSO.
pub async fn logged_out_handler() -> impl IntoResponse {
    Html(r#"<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="2;url=/">
  <title>Déconnecté — DocDockGo</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: #161614; color: #e8e6e0; display: flex; align-items: center; justify-content: center; height: 100vh; }
    .box { text-align: center; }
    .title { font-size: 17px; font-weight: 500; margin-bottom: 8px; }
    .sub { font-size: 12px; color: #5f5e5a; }
  </style>
</head>
<body>
  <div class="box">
    <div class="title">Vous êtes déconnecté</div>
    <div class="sub">Redirection vers la page de connexion…</div>
  </div>
</body>
</html>"#)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

pub fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{}=", name);
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|s| {
            let s = s.trim();
            s.strip_prefix(&prefix).map(|v| v.to_string())
        })
}

pub fn extract_role_from_cookie(headers: &HeaderMap) -> Option<String> {
    extract_cookie(headers, "role")
}

fn determine_role(claims: &ZitadelClaims) -> Option<String> {
    if let Some(ref role) = claims.role {
        let role = role.to_lowercase();
        if role == "dev" || role == "rssi" {
            return Some(role);
        }
    }
    if let Some(ref roles_value) = claims.zitadel_roles {
        if let Some(roles_obj) = roles_value.as_object() {
            for key in roles_obj.keys() {
                let key_lower = key.to_lowercase();
                if key_lower == "dev" || key_lower == "rssi" {
                    return Some(key_lower);
                }
            }
        }
    }
    None
}

fn decode_jwt_payload(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let decoded = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    String::from_utf8(decoded).ok()
}