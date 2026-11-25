use std::env;
use std::str::FromStr;

/// Settings read from environment variables (or a `.env` file).
#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub secret_key: String,
    pub access_token_expire_minutes: i64,
    pub refresh_token_expire_days: i64,
    pub cors_origins: Vec<String>,
    pub default_page_size: i64,
    pub max_page_size: i64,
    pub bind_addr: String,
}

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} must be set (see .env.example)"))
}

fn parse_or<T: FromStr>(name: &str, default: T) -> Result<T, String> {
    match env::var(name) {
        Ok(v) => v
            .parse::<T>()
            .map_err(|_| format!("{name} has an invalid value: {v}")),
        Err(_) => Ok(default),
    }
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let cors = env::var("BACKEND_CORS_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000,http://localhost:8000".to_string());

        Ok(Self {
            database_url: required("DATABASE_URL")?,
            secret_key: required("SECRET_KEY")?,
            access_token_expire_minutes: parse_or("ACCESS_TOKEN_EXPIRE_MINUTES", 30)?,
            refresh_token_expire_days: parse_or("REFRESH_TOKEN_EXPIRE_DAYS", 7)?,
            cors_origins: cors
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            default_page_size: parse_or("DEFAULT_PAGE_SIZE", 20)?,
            max_page_size: parse_or("MAX_PAGE_SIZE", 100)?,
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8000".to_string()),
        })
    }
}
