use hyper::{
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::RwLock;

const CONFIG_PATH: &str = "/tmp/docker-mitm.conf";

// Image embarquée depuis le dossier assets à la racine du projet
const LOGO_PNG: &[u8] = include_bytes!("../assets/docdockgo_logo.png");


#[derive(Clone)]
struct AppState {
    is_allowed: Arc<RwLock<bool>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Charger l'état initial depuis le fichier, ou true par défaut
    let initial = load_initial_is_allowed().unwrap_or(true);
    println!("[script] is_allowed initial = {initial}");

    let state = AppState {
        is_allowed: Arc::new(RwLock::new(initial)),
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("[script] Dashboard sur http://{addr}");

    let make_svc = make_service_fn(move |_conn| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let state = state.clone();
                async move { handle(req, state).await }
            }))
        }
    });

    Server::bind(&addr).serve(make_svc).await?;
    Ok(())
}

async fn handle(req: Request<Body>, state: AppState) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {

        // Logo
        (&Method::GET, "/logo.png") => {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "image/png")
                .body(Body::from(LOGO_PNG))
                .unwrap())
        }

        // Page principale HTML
            (&Method::GET, "/") => {
            let is_allowed = *state.is_allowed.read().await;
            let status_str = if is_allowed { "ACTIVÉES" } else { "BLOQUÉES" };
            let color = if is_allowed { "green" } else { "red" };

            // --- construction du tableau Cache / Quarantaine ---
            let cache_files = list_files_in("cache");
            let quarantine_files = list_files_in("quarantaine");

            let mut table_rows = String::new();
            let max_len = cache_files.len().max(quarantine_files.len());

            if max_len == 0 {
                table_rows.push_str(
                    "<tr>\
                       <td colspan=\"2\" style=\"border: 1px solid #ccc; padding: 4px 8px;\">\
                         <em>Aucun fichier trouvé</em>\
                       </td>\
                     </tr>",
                );
            } else {
                for i in 0..max_len {
                    let cache_name = cache_files.get(i).map(|s| s.as_str()).unwrap_or("");
                    let quar_name = quarantine_files.get(i).map(|s| s.as_str()).unwrap_or("");

                    table_rows.push_str(&format!(
                        "<tr>\
                           <td style=\"border: 1px solid #ccc; padding: 4px 8px;\">{}</td>\
                           <td style=\"border: 1px solid #ccc; padding: 4px 8px;\">{}</td>\
                         </tr>",
                        cache_name,
                        quar_name
                    ));
                }
            }
            // ---------------------------------------------------

            let body = format!(
    r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Doc Dockgo</title>
</head>
<body style="font-family: sans-serif; max-width: 600px; margin: 40px auto;">
  <div style="display:flex; align-items:center; gap:12px; margin-bottom:20px;">
    <img src="/logo.png" alt="DocDockGo" style="height:48px;">
    <h1 style="margin:0;">Doc Dockgo Proxy Dashboard</h1>
  </div>
  <p>Images : <strong style="color:{color};">{status}</strong></p>
  <form action="/toggle" method="post">
    <button type="submit" style="padding: 8px 16px;">Basculer ON/OFF</button>
  </form>
  <p style="margin-top: 20px; font-size: 0.9em; color: #555;">
    L'état est stocké dans <code>{config_path}</code> (1 = autorisées, 0 = bloquées).
  </p>

  <h2 style="margin-top: 40px;">Fichiers en cache et en quarantaine</h2>
  <table style="border-collapse: collapse; width: 100%; margin-top: 10px;">
    <thead>
      <tr>
        <th style="border: 1px solid #ccc; padding: 4px 8px; text-align: left;">Cache</th>
        <th style="border: 1px solid #ccc; padding: 4px 8px; text-align: left;">Quarantaine</th>
      </tr>
    </thead>
    <tbody>
      {table_rows}
    </tbody>
  </table>
</body>
</html>
"#,
    status = status_str,
    color = color,
    config_path = CONFIG_PATH,
    table_rows = table_rows,
);


            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/html; charset=utf-8")
                .body(Body::from(body))
                .unwrap())
        }


        // Toggle de l'état
        (&Method::POST, "/toggle") => {
            let new_value = {
                let mut lock = state.is_allowed.write().await;
                *lock = !*lock;
                *lock
            };

            if let Err(e) = save_is_allowed(new_value) {
                eprintln!("[script] Erreur d'écriture de {CONFIG_PATH}: {e}");
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Erreur d'écriture de la config"))
                    .unwrap());
            }

            println!("[script] is_allowed = {new_value}");

            // Rediriger vers la page principale
            Ok(Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header("location", "/")
                .body(Body::empty())
                .unwrap())
        }

        // 404 pour le reste
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not found"))
            .unwrap()),
    }
}

/// Lit la valeur initiale dans /tmp/docker-mitm.conf.
/// Format très simple : "1" ou "0" (avec éventuel \n).
fn load_initial_is_allowed() -> std::io::Result<bool> {
    let content = std::fs::read_to_string(CONFIG_PATH)?;
    Ok(parse_bool_from_str(&content))
}

/// Sauvegarde la valeur dans /tmp/docker-mitm.conf (1 ou 0 + \n).
fn save_is_allowed(value: bool) -> std::io::Result<()> {
    let s = if value { "1\n" } else { "0\n" };
    std::fs::write(CONFIG_PATH, s)
}

/// 1er caractère non-espace : '0' => false, sinon => true.
fn parse_bool_from_str(s: &str) -> bool {
    for ch in s.chars() {
        if ch.is_whitespace() {
            continue;
        }
        return ch != '0';
    }
    // si vide ou que des espaces, on considère "true"
    true
}

/// Retourne la liste des fichiers (noms) dans un dossier donné.
/// Ne remonte que les fichiers (pas les sous-répertoires).
fn list_files_in(dir: &str) -> Vec<String> {
    match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let path = e.path();
                if path.is_file() {
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
            .collect(),
        Err(e) => {
            eprintln!("[script] Impossible de lire le dossier {dir}: {e}");
            Vec::new()
        }
    }
}

