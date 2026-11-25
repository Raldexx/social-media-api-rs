use rustapi_rs::prelude::*;

use crate::auth;
use crate::db;
use crate::error::{db_err, ApiResult};
use crate::models::MessageResponse;
use crate::state::AppState;
use crate::validate;

#[derive(Debug, Deserialize, Schema)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub full_name: Option<String>,
}

#[derive(Debug, Deserialize, Schema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Schema)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize, Schema)]
pub struct RegisteredUser {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
    pub is_verified: bool,
}

#[derive(Debug, Serialize, Schema)]
pub struct RegisterResponse {
    pub message: String,
    pub user: RegisteredUser,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
}

#[derive(Debug, Serialize, Schema)]
pub struct LoggedInUser {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
    pub avatar_url: Option<String>,
    pub is_verified: bool,
    pub followers_count: i32,
    pub following_count: i32,
    pub posts_count: i32,
}

#[derive(Debug, Serialize, Schema)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub user: LoggedInUser,
}

#[derive(Debug, Serialize, Schema)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub token_type: String,
}

/// Create an account and log in right away.
#[rustapi_rs::post("/api/v1/auth/register")]
#[rustapi_rs::tag("Authentication")]
#[rustapi_rs::summary("Register a new user")]
async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> ApiResult<Created<RegisterResponse>> {
    let username = validate::username(&body.username)?;
    validate::email(&body.email)?;
    validate::password(&body.password)?;
    validate::max_len("full_name", body.full_name.as_deref(), 100)?;

    if db::user_by_username(&state.db, &username).await?.is_some() {
        return Err(ApiError::bad_request("Username already taken"));
    }
    if db::user_by_email(&state.db, &body.email).await?.is_some() {
        return Err(ApiError::bad_request("Email already registered"));
    }

    let role_id: i64 = sqlx::query_scalar("SELECT id FROM roles WHERE name = 'user'")
        .fetch_optional(&state.db)
        .await
        .map_err(db_err)?
        .ok_or_else(|| ApiError::internal("Default role 'user' is missing"))?;

    let hashed = auth::hash_password(body.password).await?;

    let id: i64 = sqlx::query_scalar(
        "INSERT INTO users (username, email, hashed_password, full_name, role_id) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(&username)
    .bind(&body.email)
    .bind(&hashed)
    .bind(&body.full_name)
    .bind(role_id)
    .fetch_one(&state.db)
    .await
    .map_err(db_err)?;

    let (access_token, refresh_token) = auth::issue_tokens(&state.config, id, &body.email)?;

    Ok(Created(RegisterResponse {
        message: "User registered successfully".to_string(),
        user: RegisteredUser {
            id,
            username,
            email: body.email,
            full_name: body.full_name,
            is_verified: false,
        },
        access_token,
        refresh_token,
        token_type: "bearer".to_string(),
    }))
}

/// Log in with email and password.
#[rustapi_rs::post("/api/v1/auth/login")]
#[rustapi_rs::tag("Authentication")]
#[rustapi_rs::summary("Login")]
async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let invalid = || ApiError::unauthorized("Invalid email or password");

    let user = db::user_by_email(&state.db, &body.email)
        .await?
        .ok_or_else(invalid)?;

    if !auth::verify_password(body.password, user.hashed_password.clone()).await {
        return Err(invalid());
    }
    if !user.is_active {
        return Err(ApiError::forbidden("Account is inactive. Contact support."));
    }

    let (access_token, refresh_token) = auth::issue_tokens(&state.config, user.id, &user.email)?;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        token_type: "bearer".to_string(),
        user: LoggedInUser {
            id: user.id,
            username: user.username,
            email: user.email,
            full_name: user.full_name,
            avatar_url: user.avatar_url,
            is_verified: user.is_verified,
            followers_count: user.followers_count,
            following_count: user.following_count,
            posts_count: user.posts_count,
        },
    }))
}

/// Trade a refresh token for a new access token.
#[rustapi_rs::post("/api/v1/auth/refresh")]
#[rustapi_rs::tag("Authentication")]
#[rustapi_rs::summary("Refresh access token")]
async fn refresh_token(
    State(state): State<AppState>,
    Json(body): Json<RefreshTokenRequest>,
) -> ApiResult<Json<RefreshTokenResponse>> {
    let claims = auth::decode_token(&state.config.secret_key, &body.refresh_token, auth::REFRESH)
        .ok_or_else(|| ApiError::unauthorized("Invalid or expired refresh token"))?;

    let user = db::user_by_id(&state.db, claims.user_id)
        .await?
        .filter(|u| u.is_active)
        .ok_or_else(|| ApiError::unauthorized("User not found or inactive"))?;

    let access_token = auth::create_token(
        &state.config.secret_key,
        user.id,
        &user.email,
        auth::ACCESS,
        chrono::Duration::minutes(state.config.access_token_expire_minutes),
    )?;

    Ok(Json(RefreshTokenResponse {
        access_token,
        token_type: "bearer".to_string(),
    }))
}

/// Tokens live on the client, so logging out means deleting them there.
#[rustapi_rs::post("/api/v1/auth/logout")]
#[rustapi_rs::tag("Authentication")]
#[rustapi_rs::summary("Logout")]
async fn logout() -> Json<MessageResponse> {
    Json(MessageResponse::new(
        "Logged out successfully. Please delete tokens from client.",
    ))
}

