use axum::{
    extract::Form,
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};

use serde::Deserialize;

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

pub async fn login_page() -> Html<&'static str> {
    Html(include_str!("login.html"))
}

pub async fn login_submit(Form(form): Form<LoginForm>) -> Response {
    let role = match (form.username.as_str(), form.password.as_str()) {
        ("dev", "dev123") => "dev",
        ("rssi", "rssi123") => "rssi",
        _ => return Redirect::to("/").into_response(),
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        format!("role={}; HttpOnly; Path=/", role)
            .parse()
            .unwrap(),
    );

    (headers, Redirect::to(&format!("/dashboard/{}", role))).into_response()
}

pub async fn dev_dashboard(headers: HeaderMap) -> Response {
    match extract_role_from_cookie(&headers) {
        Some("dev") => Html(include_str!("dev.html")).into_response(),
        _ => Redirect::to("/").into_response(),
    }
}

pub async fn rssi_dashboard(headers: HeaderMap) -> Response {
    match extract_role_from_cookie(&headers) {
        Some("rssi") => Html(include_str!("rssi.html")).into_response(),
        _ => Redirect::to("/").into_response(),
    }
}

pub async fn logout() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        "role=deleted; Path=/; Max-Age=0".parse().unwrap(),
    );

    (headers, Redirect::to("/")).into_response()
}

fn extract_role_from_cookie(headers: &HeaderMap) -> Option<&str> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;

    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("role=") {
            return Some(value);
        }
    }

    None
}