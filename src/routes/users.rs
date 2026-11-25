use rustapi_rs::prelude::*;

use crate::auth::{self, AuthClaims};
use crate::db;
use crate::error::{db_err, validation, ApiResult};
use crate::models::{
    MessageResponse, StatsResponse, UserListItem, UserPublicProfile, UserResponse,
};
use crate::state::AppState;
use crate::validate;

#[derive(Debug, Deserialize, Schema)]
pub struct UserUpdate {
    pub full_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Deserialize, Schema)]
pub struct PasswordUpdate {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize, Schema)]
pub struct SearchQuery {
    pub q: String,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, Schema)]
pub struct AssignRole {
    pub role_id: i64,
}

fn user_not_found() -> ApiError {
    ApiError::not_found("User not found")
}

/// `%`, `_` and `\` have a special meaning inside LIKE - search for them literally.
fn like_pattern(q: &str) -> String {
    let mut out = String::from("%");
    for c in q.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

/// Your own full profile (includes email).
#[rustapi_rs::get("/api/v1/users/me")]
#[rustapi_rs::tag("Users")]
#[rustapi_rs::summary("Get my profile")]
async fn get_my_profile(
    State(state): State<AppState>,
    claims: AuthClaims,
) -> ApiResult<Json<UserResponse>> {
    let user = auth::current_user(&state, &claims).await?;
    Ok(Json(user.into()))
}

/// Update full_name, bio and avatar_url. Fields you leave out stay as they are.
#[rustapi_rs::put("/api/v1/users/me")]
#[rustapi_rs::tag("Users")]
#[rustapi_rs::summary("Update my profile")]
async fn update_my_profile(
    State(state): State<AppState>,
    claims: AuthClaims,
    Json(body): Json<UserUpdate>,
) -> ApiResult<Json<UserResponse>> {
    let user = auth::current_user(&state, &claims).await?;
    validate::max_len("full_name", body.full_name.as_deref(), 100)?;
    validate::max_len("bio", body.bio.as_deref(), 500)?;
    validate::max_len("avatar_url", body.avatar_url.as_deref(), 255)?;

    sqlx::query(
        "UPDATE users SET full_name = COALESCE($1, full_name), bio = COALESCE($2, bio), \
         avatar_url = COALESCE($3, avatar_url), updated_at = now() WHERE id = $4",
    )
    .bind(&body.full_name)
    .bind(&body.bio)
    .bind(&body.avatar_url)
    .bind(user.id)
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    let updated = db::user_by_id(&state.db, user.id)
        .await?
        .ok_or_else(user_not_found)?;
    Ok(Json(updated.into()))
}

/// Change your password (the old one is required).
#[rustapi_rs::put("/api/v1/users/me/password")]
#[rustapi_rs::tag("Users")]
#[rustapi_rs::summary("Change my password")]
async fn change_my_password(
    State(state): State<AppState>,
    claims: AuthClaims,
    Json(body): Json<PasswordUpdate>,
) -> ApiResult<Json<MessageResponse>> {
    let user = auth::current_user(&state, &claims).await?;
    validate::password(&body.new_password)?;

    if !auth::verify_password(body.old_password, user.hashed_password.clone()).await {
        return Err(ApiError::bad_request("Old password is incorrect"));
    }

    let hashed = auth::hash_password(body.new_password).await?;
    sqlx::query("UPDATE users SET hashed_password = $1, updated_at = now() WHERE id = $2")
        .bind(hashed)
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;

    Ok(Json(MessageResponse::new("Password updated successfully")))
}

/// Deactivate your account (it is not deleted).
#[rustapi_rs::delete("/api/v1/users/me")]
#[rustapi_rs::tag("Users")]
#[rustapi_rs::summary("Deactivate my account")]
async fn deactivate_my_account(
    State(state): State<AppState>,
    claims: AuthClaims,
) -> ApiResult<Json<MessageResponse>> {
    let user = auth::current_user(&state, &claims).await?;
    sqlx::query("UPDATE users SET is_active = FALSE, updated_at = now() WHERE id = $1")
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;
    Ok(Json(MessageResponse::new("Account deactivated successfully")))
}

#[rustapi_rs::get("/api/v1/users/me/stats")]
#[rustapi_rs::tag("Users")]
#[rustapi_rs::summary("My followers / following / posts counts")]
async fn get_my_stats(
    State(state): State<AppState>,
    claims: AuthClaims,
) -> ApiResult<Json<StatsResponse>> {
    let user = auth::current_user(&state, &claims).await?;
    Ok(Json(StatsResponse {
        followers_count: user.followers_count,
        following_count: user.following_count,
        posts_count: user.posts_count,
    }))
}

/// Case-insensitive search in username and full name. Active users only.
#[rustapi_rs::get("/api/v1/users/search")]
#[rustapi_rs::tag("Users")]
#[rustapi_rs::summary("Search users")]
async fn search_users(
    State(state): State<AppState>,
    Query(params): Query<SearchQuery>,
) -> ApiResult<Json<Vec<UserListItem>>> {
    if params.q.is_empty() {
        return Err(validation("q must not be empty"));
    }
    let limit = params.limit.unwrap_or(state.config.default_page_size);
    if !(1..=state.config.max_page_size).contains(&limit) {
        return Err(validation(format!(
            "limit must be between 1 and {}",
            state.config.max_page_size
        )));
    }

    let users = sqlx::query_as::<_, UserListItem>(
        "SELECT id, username, full_name, avatar_url, is_verified FROM users \
         WHERE is_active AND (username ILIKE $1 OR full_name ILIKE $1) \
         ORDER BY username LIMIT $2",
    )
    .bind(like_pattern(&params.q))
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;

    Ok(Json(users))
}

/// Public profile by username (no email, no login needed).
#[rustapi_rs::get("/api/v1/users/{key}")]
#[rustapi_rs::tag("Users")]
#[rustapi_rs::summary("Get a public profile by username")]
async fn get_user_profile(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> ApiResult<Json<UserPublicProfile>> {
    let user = db::user_by_username(&state.db, &username)
        .await?
        .ok_or_else(user_not_found)?;
    Ok(Json(user.into()))
}

/// Counts of a user, by numeric id.
#[rustapi_rs::get("/api/v1/users/{key}/stats")]
#[rustapi_rs::tag("Users")]
#[rustapi_rs::summary("Get a user's counts by id")]
async fn get_user_stats(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
) -> ApiResult<Json<StatsResponse>> {
    let user = db::user_by_id(&state.db, user_id)
        .await?
        .ok_or_else(user_not_found)?;
    Ok(Json(StatsResponse {
        followers_count: user.followers_count,
        following_count: user.following_count,
        posts_count: user.posts_count,
    }))
}

/// Give a user a different role (admin only).
#[rustapi_rs::put("/api/v1/users/{key}/role")]
#[rustapi_rs::tag("Users")]
#[rustapi_rs::summary("Assign a role to a user (admin)")]
async fn assign_role(
    State(state): State<AppState>,
    claims: AuthClaims,
    Path(username): Path<String>,
    Json(body): Json<AssignRole>,
) -> ApiResult<Json<UserResponse>> {
    auth::require_admin(&state, &claims).await?;

    let role = db::role_by_id(&state.db, body.role_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Role not found"))?;
    if !role.is_active {
        return Err(ApiError::bad_request("Role is not active"));
    }

    let target = db::user_by_username(&state.db, &username)
        .await?
        .ok_or_else(user_not_found)?;

    sqlx::query("UPDATE users SET role_id = $1, updated_at = now() WHERE id = $2")
        .bind(role.id)
        .bind(target.id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;

    let updated = db::user_by_id(&state.db, target.id)
        .await?
        .ok_or_else(user_not_found)?;
    Ok(Json(updated.into()))
}
