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
    /// AES-256-GCM symmetric key used to E2EE payloads with the Verifier
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
            aes_secret_key: String::from("pos-captcha-secret-key-32-bytes!"),
        }
    }

    pub fn load() -> Config {
        let config_path = PathBuf::from("pos-config.json");
        if config_path.exists() {
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
        }
    }
}
