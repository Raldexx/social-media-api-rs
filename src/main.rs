mod auth;
mod config;
mod db;
mod error;
mod models;
mod routes;
mod state;
mod validate;

use std::sync::Arc;

use http::Method;
use rustapi_rs::prelude::*;
use sqlx::postgres::PgPoolOptions;

use crate::config::Config;
use crate::state::AppState;

#[derive(Debug, Serialize, Schema)]
struct EndpointList {
    auth: &'static str,
    users: &'static str,
    roles: &'static str,
    posts: &'static str,
}

#[derive(Debug, Serialize, Schema)]
struct RootInfo {
    message: &'static str,
    version: &'static str,
    docs: &'static str,
    endpoints: EndpointList,
}

#[rustapi_rs::get("/")]
#[rustapi_rs::tag("Info")]
#[rustapi_rs::summary("API info")]
async fn root() -> Json<RootInfo> {
    Json(RootInfo {
        message: "Welcome to Social Media API!",
        version: env!("CARGO_PKG_VERSION"),
        docs: "/docs",
        endpoints: EndpointList {
            auth: "/api/v1/auth",
            users: "/api/v1/users",
            roles: "/api/v1/roles",
            posts: "/api/v1/posts",
        },
    })
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();

    let config = Config::from_env()?;

    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;
    // Creates / updates the tables (see the `migrations` folder).
    sqlx::migrate!().run(&db).await?;
    tracing::info!("database ready");

    let cors = CorsLayer::new()
        .allow_origins(config.cors_origins.clone())
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(["authorization", "content-type"])
        .allow_credentials(true);

    let bind_addr = config.bind_addr.clone();
    let state = AppState {
        db,
        config: Arc::new(config),
    };

    tracing::info!("listening on http://{bind_addr}  (docs: http://{bind_addr}/docs)");

    RustApi::auto()
        .state(state)
        .layer(cors)
        .production_defaults("social-media-api")
        .run_with_shutdown(&bind_addr, async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await
}
