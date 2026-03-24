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