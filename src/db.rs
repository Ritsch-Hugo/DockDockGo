use anyhow::Result;
use sqlx::PgPool;

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
    image_key: &str,
    list: &str, // "whitelist" ou "blacklist"
) -> Result<bool> {
    let query = match list {
        "whitelist" => "SELECT COUNT(*) FROM whitelist WHERE image = $1",
        "blacklist" => "SELECT COUNT(*) FROM blacklist WHERE image = $1",
        _ => return Ok(false),
    };

    let count: i64 = sqlx::query_scalar(query)
        .bind(image_key)
        .fetch_one(pool)
        .await?;

    Ok(count > 0)
}

/// Ajoute une image dans la whitelist ou blacklist
pub async fn add_image_to_list(
    pool: &PgPool,
    image_key: &str,
    list: &str, // "whitelist" ou "blacklist"
) -> Result<()> {
    let query = match list {
        "whitelist" => "INSERT INTO whitelist (image) VALUES ($1) ON CONFLICT DO NOTHING",
        "blacklist" => "INSERT INTO blacklist (image) VALUES ($1) ON CONFLICT DO NOTHING",
        _ => return Ok(()),
    };

    sqlx::query(query)
        .bind(image_key)
        .execute(pool)
        .await?;

    println!("[DB] Ajouté dans {} : {}", list, image_key);
    Ok(())
}