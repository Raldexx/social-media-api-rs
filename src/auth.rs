use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rustapi_openapi::{Operation, OperationModifier};
use rustapi_rs::core::FromRequestParts;
use rustapi_rs::prelude::*;

use crate::config::Config;
use crate::db;
use crate::error::{ApiResult};
use crate::models::{RoleRow, UserRow};
use crate::state::AppState;

pub const ACCESS: &str = "access";
pub const REFRESH: &str = "refresh";

/// What we put inside a token. `typ` makes sure a refresh token can never be
/// used as an access token (and the other way around).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: i64,
    pub email: String,
    pub typ: String,
    pub exp: u64,
}

pub fn create_token(
    secret: &str,
    user_id: i64,
    email: &str,
    typ: &str,
    ttl: Duration,
) -> ApiResult<String> {
    let claims = Claims {
        user_id,
        email: email.to_string(),
        typ: typ.to_string(),
        exp: (Utc::now() + ttl).timestamp() as u64,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| ApiError::internal("Could not create token").with_internal(e.to_string()))
}

/// (access_token, refresh_token)
pub fn issue_tokens(config: &Config, user_id: i64, email: &str) -> ApiResult<(String, String)> {
    let access = create_token(
        &config.secret_key,
        user_id,
        email,
        ACCESS,
        Duration::minutes(config.access_token_expire_minutes),
    )?;
    let refresh = create_token(
        &config.secret_key,
        user_id,
        email,
        REFRESH,
        Duration::days(config.refresh_token_expire_days),
    )?;
    Ok((access, refresh))
}

/// Returns the claims only if the signature is valid, the token has not
/// expired and it is of the expected kind.
pub fn decode_token(secret: &str, token: &str, expected_typ: &str) -> Option<Claims> {
    let mut validation = Validation::default();
    validation.leeway = 0;
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()?;
    (data.claims.typ == expected_typ).then_some(data.claims)
}

// Argon2 is slow on purpose, so it runs on a blocking thread and does not
// stall the async server.

pub async fn hash_password(password: String) -> ApiResult<String> {
    let result = tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
    })
    .await
    .map_err(|e| ApiError::internal("Could not hash password").with_internal(e.to_string()))?;

    result.map_err(|e| ApiError::internal("Could not hash password").with_internal(e.to_string()))
}

pub async fn verify_password(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || match PasswordHash::new(&hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    })
    .await
    .unwrap_or(false)
}

// ------------------------------------------------------------- extractor

/// Put this in a handler's arguments to require `Authorization: Bearer <access token>`.
/// It only checks the token; use [`current_user`] to load the user.
#[derive(Debug, Clone)]
pub struct AuthClaims(pub Claims);

impl FromRequestParts for AuthClaims {
    fn from_request_parts(req: &Request) -> rustapi_rs::Result<Self> {
        let unauthorized = || ApiError::unauthorized("Could not validate credentials");

        let state = req
            .state()
            .get::<AppState>()
            .ok_or_else(|| ApiError::internal("Application state is missing"))?;

        let header = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(unauthorized)?;

        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .ok_or_else(unauthorized)?;

        decode_token(&state.config.secret_key, token, ACCESS)
            .map(AuthClaims)
            .ok_or_else(unauthorized)
    }
}

impl OperationModifier for AuthClaims {
    fn update_operation(_op: &mut Operation) {}
}

// -------------------------------------------------------- loading the user

/// Load the logged-in user: 401 if they no longer exist, 403 if deactivated.
pub async fn current_user(state: &AppState, claims: &AuthClaims) -> ApiResult<UserRow> {
    let user = db::user_by_id(&state.db, claims.0.user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Could not validate credentials"))?;
    if !user.is_active {
        return Err(ApiError::forbidden("User account is inactive"));
    }
    Ok(user)
}

/// Admin-only endpoints.
pub async fn require_admin(state: &AppState, claims: &AuthClaims) -> ApiResult<UserRow> {
    let user = current_user(state, claims).await?;
    if !user.is_superuser {
        return Err(ApiError::forbidden(
            "Not enough permissions. Admin access required.",
        ));
    }
    Ok(user)
}

/// The user's role. Every user has one (the column is NOT NULL).
pub async fn role_of(state: &AppState, user: &UserRow) -> ApiResult<RoleRow> {
    db::role_by_id(&state.db, user.role_id)
        .await?
        .ok_or_else(|| ApiError::internal("User role is missing"))
}

/// Admins can always do it; everyone else needs an active role with the permission.
pub fn allowed(user: &UserRow, role: &RoleRow, permission: impl Fn(&RoleRow) -> bool) -> bool {
    user.is_superuser || (role.is_active && permission(role))
}
