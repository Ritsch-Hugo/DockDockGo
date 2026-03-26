    use dashmap::DashMap;
    use once_cell::sync::Lazy;
    use serde::Serialize;
    use uuid::Uuid;

    #[derive(Debug, Clone, Serialize)]
    pub struct ScanResult {
        pub pull_id: Uuid,
        pub image_name: String,
        pub status: String, // "ALLOW" ou "DENY"
        pub score: u8,
    }

    // La "base de données" partagée
    pub static SCAN_RESULTS: Lazy<DashMap<Uuid, ScanResult>> = Lazy::new(DashMap::new);