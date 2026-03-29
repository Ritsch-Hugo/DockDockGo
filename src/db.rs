use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

/// Initialise le pool de connexions PostgreSQL
pub async fn init_pool(database_url: &str) -> Result<PgPool> {
    let pool = PgPool::connect(database_url).await?;
    println!("[DB] Connecté à PostgreSQL");
    Ok(pool)
}

/// Vérifie si une image est dans la whitelist ou blacklist
/// Retourne true si trouvée
pub async fn is_image_in_list(
    pool: &PgPool,
    registry: &str,
    repository: &str,
    tag: &str,
    list: &str,
) -> Result<bool> {
    let table = match list {
        "whitelist" => "whitelist",
        "blacklist" => "blacklist",
        _ => return Ok(false),
    };

    let query = format!(
        "SELECT COUNT(*) FROM {} WHERE registry = $1 AND repository = $2 AND tag = $3",
        table
    );

    let count: i64 = sqlx::query_scalar(&query)
        .bind(registry)
        .bind(repository)
        .bind(tag)
        .fetch_one(pool)
        .await?;

    Ok(count > 0)
}

/// Ajoute une image dans la whitelist ou blacklist
pub async fn add_image_to_list(
    pool: &PgPool,
    registry: &str,
    repository: &str,
    tag: &str,
    list: &str,
) -> Result<()> {
    let table = match list {
        "whitelist" => "whitelist",
        "blacklist" => "blacklist",
        _ => return Ok(()),
    };

    let query = format!(
        "INSERT INTO {} (id, registry, repository, tag) 
        VALUES ($1::uuid, $2, $3, $4) 
        ON CONFLICT DO NOTHING",
        table
    );

    sqlx::query(&query)
        .bind(Uuid::new_v4().to_string())
        .bind(registry)
        .bind(repository)
        .bind(tag)
        .execute(pool)
        .await?;

    println!("[DB] Ajouté dans {} : {}/{} :{}", list, registry, repository, tag);
    Ok(())
}

/// Ajoute ou met à jour un fichier dans la table quarantine
pub async fn upsert_quarantine_file(
    pool: &PgPool,
    registry: &str,
    repository: &str,
    digest: &str,        // "sha256:abc123..."
    file_type: &str,     // "manifest", "blob", "referrer"
    digest_algo: &str,   // "sha256"
    file_path: &str,
    size_bytes: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO quarantine (id, registry, repository, digest, type, digest_algo, file_path, size_bytes, added_at)
         VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, NOW())
         ON CONFLICT (registry, repository, digest, type)
         DO UPDATE SET file_path = EXCLUDED.file_path,
                       size_bytes = EXCLUDED.size_bytes,
                       added_at = NOW()"
    )
    .bind(Uuid::new_v4().to_string())
    .bind(registry)
    .bind(repository)
    .bind(digest)
    .bind(file_type)
    .bind(digest_algo)
    .bind(file_path)
    .bind(size_bytes)
    .execute(pool)
    .await?;
    Ok(())
}

/// Supprime un fichier de la table quarantine
pub async fn delete_quarantine_file(
    pool: &PgPool,
    registry: &str,
    repository: &str,
    digest: &str,
    file_type: &str,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM quarantine
         WHERE registry = $1 AND repository = $2 AND digest = $3 AND type = $4"
    )
    .bind(registry)
    .bind(repository)
    .bind(digest)
    .bind(file_type)
    .execute(pool)
    .await?;
    Ok(())
}

/// Ajoute ou met à jour un fichier dans la table cache
pub async fn upsert_cache_file(
    pool: &PgPool,
    registry: &str,
    repository: &str,
    digest: &str,
    file_type: &str,
    digest_algo: &str,
    file_path: &str,
    size_bytes: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO cache (id, registry, repository, digest, type, digest_algo, file_path, size_bytes, added_at)
         VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, NOW())
         ON CONFLICT (registry, repository, digest, type)
         DO UPDATE SET file_path = EXCLUDED.file_path,
                       size_bytes = EXCLUDED.size_bytes,
                       added_at = NOW()"
    )
    .bind(Uuid::new_v4().to_string())
    .bind(registry)
    .bind(repository)
    .bind(digest)
    .bind(file_type)
    .bind(digest_algo)
    .bind(file_path)
    .bind(size_bytes)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn is_ip_allowed(pool: &sqlx::PgPool, ip: &str) -> bool {
    // On utilise query_scalar sans "!" pour éviter les erreurs de compilation DATABASE_URL
    let result = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE $1 = ANY(allowed_ips))"
    )
    .bind(ip)
    .fetch_one(pool)
    .await;

    match result {
        Ok(true) => {
            println!("[DB] IP autorisée : {}", ip);
            true
        }
        _ => {
            // En cas d'erreur ou de non-trouvé, on refuse (Fail Closed)
            println!("[SECURITY] IP refusée ou erreur DB : {}", ip);
            false
        }
    }
}
