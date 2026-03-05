use anyhow::Result;
use reqwest::Client;

pub enum RegistryClient {
    DockerHub,
    Generic(String),
}

impl RegistryClient {
    pub fn from_registry(registry: &str) -> Self {
        match registry {
            "registry-1.docker.io" => RegistryClient::DockerHub,
            other => RegistryClient::Generic(other.to_string()),
        }
    }

    pub fn registry_host(&self) -> &str {
        match self {
            RegistryClient::DockerHub => "registry-1.docker.io",
            RegistryClient::Generic(r) => r.as_str(),
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
                let manifest_url = format!(
                    "https://{}/v2/{}/manifests/latest",
                    registry, repository
                );

                // Appel sans token pour récupérer le Www-Authenticate
                let resp_unauth = client
                    .get(&manifest_url)
                    .header(
                        "Accept",
                        "application/vnd.docker.distribution.manifest.list.v2+json,\
                        application/vnd.docker.distribution.manifest.v2+json,\
                        application/vnd.oci.image.index.v1+json,\
                        application/vnd.oci.image.manifest.v1+json",
                    )
                    .send()
                    .await?;

                let www_auth = resp_unauth
                    .headers()
                    .get("Www-Authenticate")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| anyhow::anyhow!("Www-Authenticate manquant pour {}", registry))?
                    .to_string();

                get_token_from_www_authenticate(client, &www_auth).await
            }
        }
    }
}

async fn get_token_from_www_authenticate(
    client: &Client,
    www_auth: &str,
) -> Result<String, anyhow::Error> {
    let realm = extract_www_auth_field(www_auth, "realm")
        .ok_or_else(|| anyhow::anyhow!("realm manquant dans Www-Authenticate"))?;
    let service = extract_www_auth_field(www_auth, "service").unwrap_or_default();
    let scope = extract_www_auth_field(www_auth, "scope").unwrap_or_default();

    let mut token_url = format!("{}?", realm);
    if !service.is_empty() {
        token_url.push_str(&format!("service={}&", service));
    }
    if !scope.is_empty() {
        token_url.push_str(&format!("scope={}", scope));
    }

    println!("[AUTH] Token URL: {}", token_url);
    println!("[AUTH] Www-Authenticate brut: {}", www_auth); // ← ajoute ça

    let resp = client.get(&token_url).send().await?;
    let text = resp.text().await?;
    println!("[AUTH] Réponse brute: {}", text); // ← et ça

    let json: serde_json::Value = serde_json::from_str(&text)?;

    let token = json
        .get("token")
        .or_else(|| json.get("access_token"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Token manquant dans la réponse auth"))?;

    Ok(token.to_string())
}

fn extract_www_auth_field(www_auth: &str, field: &str) -> Option<String> {
    let pattern = format!("{}=\"", field);
    let start = www_auth.find(&pattern)? + pattern.len();
    let end = www_auth[start..].find('"')? + start;
    Some(www_auth[start..end].to_string())
}