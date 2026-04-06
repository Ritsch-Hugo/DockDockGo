use anyhow::Result;
use reqwest::Client;
use url::Url;

pub enum RegistryClient {
    DockerHub,
    Generic(String),
}

impl RegistryClient {
    //on fabrique l'enum en fonction du registre
    pub fn from_registry(registry: &str) -> Self {
        match registry {
            "registry-1.docker.io" => RegistryClient::DockerHub,
            other => RegistryClient::Generic(other.to_string()),
        }
    }

    pub async fn get_token(
        &self,
        client: &Client,
        repository: &str,
    ) -> Result<String, anyhow::Error> {
        match self {
            // ← comportement Docker Hub inchangé
            RegistryClient::DockerHub => {
                let url = format!(
                    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
                    repository
                );
                let resp: serde_json::Value = client.get(url).send().await?.json().await?;
                let token = resp["token"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Token Docker Hub manquant"))?;
                Ok(token.to_string())
            }

            // ← comportement générique via Www-Authenticate
            RegistryClient::Generic(registry) => {
                let ping_url = format!("https://{}/v2/", registry);

                let resp_unauth = client.get(&ping_url).send().await?;

                let www_auth = resp_unauth
                    .headers()
                    .get("Www-Authenticate")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| anyhow::anyhow!("Www-Authenticate manquant pour {}", registry))?
                    .to_string();

                // Extraire realm et service, ignorer le scope du header
                let realm = extract_www_auth_field(&www_auth, "realm")
                    .ok_or_else(|| anyhow::anyhow!("realm manquant"))?;

                //Validation anti SSRF
                validate_realm(&realm, registry)?;

                let service = extract_www_auth_field(&www_auth, "service").unwrap_or_default();

                // Construire l'URL avec le bon scope
                let token_url = format!(
                    "{}?service={}&scope=repository:{}:pull",
                    realm, service, repository
                );

                println!("[AUTH] Token URL: {}", token_url);

                let resp = client.get(&token_url).send().await?;
                let text = resp.text().await?;
                println!("[AUTH] Réponse brute: {}", text);

                let json: serde_json::Value = serde_json::from_str(&text)?;
                let token = json
                    .get("token")
                    .or_else(|| json.get("access_token"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Token manquant dans la réponse auth"))?;

                Ok(token.to_string())
            }
        }
    }
}

//parseur de header
fn extract_www_auth_field(www_auth: &str, field: &str) -> Option<String> {
    let pattern = format!("{}=\"", field);
    let start = www_auth.find(&pattern)? + pattern.len();
    let end = www_auth[start..].find('"')? + start;
    Some(www_auth[start..end].to_string())
}

//Patterns de validation pour les headers et les champs d'authentification (anti SSRF))
fn validate_realm(realm: &str, expected_registry: &str) -> Result<(), anyhow::Error> {
    let parsed = Url::parse(realm).map_err(|_| anyhow::anyhow!("Realm URL invalide: {}", realm))?;

    // Schéma obligatoirement HTTPS
    if parsed.scheme() != "https" {
        return Err(anyhow::anyhow!("Realm non-HTTPS rejeté: {}", realm));
    }

    let realm_host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Realm sans host: {}", realm))?;

    // Le host du realm doit correspondre au registre attendu
    // On autorise aussi les sous-domaines directs (ex: auth.ghcr.io pour ghcr.io)
    let registry_host = expected_registry
        .split(':') // retire le port éventuel
        .next()
        .unwrap_or(expected_registry);

    let ok = realm_host == registry_host || realm_host.ends_with(&format!(".{}", registry_host));

    if !ok {
        return Err(anyhow::anyhow!(
            "SSRF bloqué — realm '{}' ne correspond pas au registre '{}'",
            realm_host,
            registry_host
        ));
    }

    Ok(())
}
