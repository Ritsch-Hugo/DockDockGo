use axum::{
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
};
use crate::auth;
use crate::dashboard::store::SCAN_RESULTS;

pub async fn dev_dashboard(headers: HeaderMap) -> Response {
    // Vérification du rôle via ton module auth
    if auth::extract_role_from_cookie(&headers) != Some("dev") {
        return Redirect::to("/").into_response();
    }

    let mut rows = String::new();
    for entry in SCAN_RESULTS.iter() {
        let res = entry.value();
        rows.push_str(&format!(
            "<tr>
                <td>{}</td>
                <td>{}</td>
                <td>{}%</td>
                <td style='color: {}'><b>{}</b></td>
            </tr>",
            res.pull_id, 
            res.image_name, 
            res.score, 
            if res.status == "ALLOW" { "green" } else { "red" },
            res.status
        ));
    }

    // Adapte le chemin si tes HTML sont à la racine ou dans /templates
    let html = include_str!("../../template/dev.html").replace("", &rows);
    Html(html).into_response()
}

pub async fn rssi_dashboard(headers: HeaderMap) -> Response {
    if auth::extract_role_from_cookie(&headers) != Some("rssi") {
        return Redirect::to("/").into_response();
    }
    Html(include_str!("../../template/rssi.html")).into_response()
}