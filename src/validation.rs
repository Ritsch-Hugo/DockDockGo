/// Erreur de validation
#[derive(Debug)]
pub enum ValidationError {
    InvalidRegistry(String),
    InvalidRepository(String),
    InvalidTag(String),
    InvalidDigest(String),
    HeadersTooLarge(usize),
    SuspiciousHeader(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::InvalidRegistry(s)   => write!(f, "Registre invalide: {}", s),
            ValidationError::InvalidRepository(s) => write!(f, "Repository invalide: {}", s),
            ValidationError::InvalidTag(s)        => write!(f, "Tag invalide: {}", s),
            ValidationError::InvalidDigest(s)     => write!(f, "Digest invalide: {}", s),
            ValidationError::HeadersTooLarge(n)   => write!(f, "Headers trop volumineux: {} bytes", n),
            ValidationError::SuspiciousHeader(s)  => write!(f, "Header suspect: {}", s),
        }
    }
}

/// Valide uniquement les headers — appelée pour TOUTES les requêtes y compris /v2/
pub fn validate_headers(req: &hyper::Request<hyper::Body>) -> Result<(), ValidationError> {
    // Vérification taille totale des headers
    let headers_size: usize = req.headers()
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len())
        .sum();

    if headers_size > 8 * 1024 {
        return Err(ValidationError::HeadersTooLarge(headers_size));
    }

    // Vérification patterns suspects dans TOUS les headers (pas seulement User-Agent)
    let suspicious_patterns = ["${jndi:", "{{", "<%", "cmd.exe", "/bin/sh"];
    for (_, v) in req.headers().iter() {
        if let Ok(val) = v.to_str() {
            if suspicious_patterns.iter().any(|p| val.contains(p)) {
                return Err(ValidationError::SuspiciousHeader(val.to_string()));
            }
        }
    }

    Ok(())
}

/// Valide le nom du registre
pub fn validate_registry(registry: &str) -> Result<(), ValidationError> {
    if registry.is_empty() || registry.len() > 255 {
        return Err(ValidationError::InvalidRegistry(registry.to_string()));
    }

    let valid = registry.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':'
    });

    if !valid {
        return Err(ValidationError::InvalidRegistry(registry.to_string()));
    }

    if registry.contains("..") || registry.contains('/') || registry.contains('\\') {
        return Err(ValidationError::InvalidRegistry(registry.to_string()));
    }

    Ok(())
}

/// Valide le nom du repository
pub fn validate_repository(repository: &str) -> Result<(), ValidationError> {
    if repository.is_empty() || repository.len() > 255 {
        return Err(ValidationError::InvalidRepository(repository.to_string()));
    }

    let valid = repository.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '/' || c == '-' || c == '_' || c == '.'
    });

    if !valid {
        return Err(ValidationError::InvalidRepository(repository.to_string()));
    }

    if repository.contains("..") || repository.contains('\\') {
        return Err(ValidationError::InvalidRepository(repository.to_string()));
    }

    if repository.starts_with('/') || repository.ends_with('/') {
        return Err(ValidationError::InvalidRepository(repository.to_string()));
    }

    Ok(())
}

/// Valide un tag ou digest
pub fn validate_tag_or_digest(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > 255 {
        return Err(ValidationError::InvalidTag(value.to_string()));
    }

    if value.starts_with("sha256:") {
        let hex_part = &value[7..];
        if hex_part.len() != 64 {
            return Err(ValidationError::InvalidDigest(value.to_string()));
        }
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ValidationError::InvalidDigest(value.to_string()));
        }
    } else {
        let valid = value.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
        });
        if !valid {
            return Err(ValidationError::InvalidTag(value.to_string()));
        }
    }

    Ok(())
}

/// Valide les composants du path (registry, repository, tag/digest)
pub fn validate_request_components(
    registry: &str,
    repository: &str,
    tag_or_digest: &str,
) -> Result<(), ValidationError> {
    validate_registry(registry)?;
    validate_repository(repository)?;
    validate_tag_or_digest(tag_or_digest)?;
    Ok(())
}