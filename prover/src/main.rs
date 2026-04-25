mod block_generation;
mod merkle_tree;
mod communication;
mod api;
mod plotter;
mod config;
mod crypto;
mod consent;

use actix_web::{web, App, HttpServer, middleware};
use actix_cors::Cors;
use std::sync::{Arc, Mutex};
use std::fs::File;

use crate::api::AppState;
use crate::config::Config;
use crate::plotter::Plotter;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    log::info!("PoS-Prover starting...");

    let config = Config::load();
    log::info!("Config loaded: port={}, storage_size_mb={}", config.port, config.storage_size_mb);

    // Initialize the plotter and perform initial plotting if needed
    let plotter = Plotter::new(&config);
    let (output_file, root_hashes, num_block_groups) = plotter.ensure_plotted();

    log::info!(
        "Plot ready: {} block groups, {} root hashes",
        num_block_groups,
        root_hashes.len()
    );

    let state = web::Data::new(AppState {
        status: Mutex::new(api::ServiceStatus::Ready),
        output_file: Mutex::new(output_file),
        root_hashes: root_hashes,
        num_block_groups: num_block_groups as u64,
        config: config.clone(),
        consent: crate::consent::ConsentRegistry::new(),
    });

    let allowed_origins = config.allowed_origins.clone();
    let port = config.port;

    log::info!("Starting HTTP server on 127.0.0.1:{}", port);

    HttpServer::new(move || {
        let mut cors = Cors::default()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        for origin in &allowed_origins {
            cors = cors.allowed_origin(origin);
        }
        // Always allow the browser extension (localhost)
        cors = cors.allowed_origin(&format!("http://127.0.0.1:{}", port));

        App::new()
            .app_data(state.clone())
            .wrap(cors)
            .route("/status", web::get().to(api::get_status))
            .route("/commitment", web::get().to(api::get_commitment))
            .route("/challenge", web::post().to(api::handle_challenge))
            .route("/inclusion-proofs", web::post().to(api::handle_inclusion_proofs))
            .route("/pending-consent", web::get().to(api::list_pending_consent))
            .route("/consent", web::post().to(api::submit_consent))
    })
    .bind(format!("127.0.0.1:{}", port))?
    .run()
    .await
}
