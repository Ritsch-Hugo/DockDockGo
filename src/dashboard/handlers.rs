use axum::{
    extract::State,
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
};
use crate::auth::{extract_role_from_cookie, OidcState};
use crate::dashboard::store::SCAN_RESULTS;
use crate::auth::AppState;

pub async fn dev_dashboard(
    State(_state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    match extract_role_from_cookie(&headers).as_deref() {
        Some("dev") => (),
        _ => return Redirect::to("/").into_response(),
    }

    let mut rows = String::new();
    for entry in SCAN_RESULTS.iter() {
        let res = entry.value();
        let status_class = if res.status == "ALLOW" { "badge-green" } else { "badge-red" };
        rows.push_str(&format!(
            "<tr>
                <td>{}</td>
                <td>{}</td>
                <td><span class='chip'>{}%</span></td>
                <td><span class='badge {}'>{}</span></td>
            </tr>",
            res.pull_id, res.image_name, res.score, status_class, res.status
        ));
    }

    let html = include_str!("../../template/dev.html").replace("{{SCAN_ROWS}}", &rows);
    Html(html).into_response()
}

pub async fn rssi_dashboard(
    State(_state): State<AppState>, // On change le type ici aussi
    headers: HeaderMap,
) -> Response {
    match extract_role_from_cookie(&headers).as_deref() {
        Some("rssi") => (),
        _ => return Redirect::to("/").into_response(),
    }

    Html(include_str!("../../template/rssi.html")).into_response()
}