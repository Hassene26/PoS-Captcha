use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Port for the local HTTP server
    pub port: u16,
    /// Size of storage to allocate in MB
    pub storage_size_mb: u64,
    /// Path to the output.bin plot file
    pub plot_path: String,
    /// Allowed CORS origins (remote verifier domains)
    pub allowed_origins: Vec<String>,
    /// AES-256-GCM symmetric key (hex-encoded, 64 hex chars = 32 bytes).
    /// Loaded from AES_SECRET_KEY env var; falls back to config file value.
    #[serde(default)]
    pub aes_secret_key: String,
}

impl Config {
    pub fn default_config() -> Config {
        Config {
            port: 7331,
            storage_size_mb: 64,
            plot_path: String::from("output.bin"),
            allowed_origins: vec![
                String::from("http://localhost:3000"),
                String::from("http://127.0.0.1:3000"),
            ],
            aes_secret_key: String::new(),
        }
    }

    pub fn load() -> Config {
        let config_path = PathBuf::from("pos-config.json");
        let mut config = if config_path.exists() {
            let content = fs::read_to_string(&config_path)
                .expect("Failed to read config file");
            serde_json::from_str(&content)
                .expect("Failed to parse config file")
        } else {
            let config = Config::default_config();
            let content = serde_json::to_string_pretty(&config).unwrap();
            fs::write(&config_path, content)
                .expect("Failed to write default config");
            log::info!("Created default config file: pos-config.json");
            config
        };

        // Env var overrides config file
        if let Ok(env_key) = std::env::var("AES_SECRET_KEY") {
            config.aes_secret_key = env_key;
        }

        // Validate: must be 64 hex chars (32 bytes)
        let key = &config.aes_secret_key;
        if key.is_empty() || key == "pos-captcha-secret-key-32-bytes!" {
            panic!(
                "\n[FATAL] AES_SECRET_KEY is not set or is still the insecure default.\n\
                 Generate one with: openssl rand -hex 32\n\
                 Then export it:    export AES_SECRET_KEY=<your-64-hex-char-key>\n\
                 Or set it in pos-config.json under \"aes_secret_key\".\n"
            );
        }
        if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
            panic!(
                "\n[FATAL] AES_SECRET_KEY must be exactly 64 hex characters (32 bytes).\n\
                 Generate one with: openssl rand -hex 32\n"
            );
        }

        config
    }
}
