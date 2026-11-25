use rustapi_rs::prelude::*;

use crate::auth::{self, AuthClaims};
use crate::db;
use crate::error::{db_err, validation, ApiResult};
use crate::models::{MessageResponse, RoleListItem, RoleResponse, RoleRow};
use crate::state::AppState;
use crate::validate;

fn yes() -> bool {
    true
}
fn hundred() -> i32 {
    100
}
fn ten_thousand() -> i32 {
    10_000
}

#[derive(Debug, Deserialize, Schema)]
pub struct RoleCreate {
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "yes")]
    pub can_post: bool,
    #[serde(default = "yes")]
    pub can_comment: bool,
    #[serde(default = "yes")]
    pub can_like: bool,
    #[serde(default = "yes")]
    pub can_delete_own_posts: bool,
    #[serde(default)]
    pub can_delete_any_posts: bool,
    #[serde(default)]
    pub can_ban_users: bool,
    #[serde(default)]
    pub can_verify_users: bool,
    #[serde(default)]
    pub can_manage_roles: bool,
    #[serde(default = "hundred")]
    pub max_posts_per_day: i32,
    #[serde(default = "ten_thousand")]
    pub max_followers: i32,
}

#[derive(Debug, Deserialize, Schema)]
pub struct RoleUpdate {
    pub description: Option<String>,
    pub can_post: Option<bool>,
    pub can_comment: Option<bool>,
    pub can_like: Option<bool>,
    pub can_delete_own_posts: Option<bool>,
    pub can_delete_any_posts: Option<bool>,
    pub can_ban_users: Option<bool>,
    pub can_verify_users: Option<bool>,
    pub can_manage_roles: Option<bool>,
    pub max_posts_per_day: Option<i32>,
    pub max_followers: Option<i32>,
}

fn role_not_found() -> ApiError {
    ApiError::not_found("Role not found")
}

fn non_negative(field: &str, v: Option<i32>) -> ApiResult<()> {
    match v {
        Some(n) if n < 0 => Err(validation(format!("{field} must be 0 or greater"))),
        _ => Ok(()),
    }
}

/// Create a role (admin only).
#[rustapi_rs::post("/api/v1/roles")]
#[rustapi_rs::tag("Roles")]
#[rustapi_rs::summary("Create a role (admin)")]
async fn create_role(
    State(state): State<AppState>,
    claims: AuthClaims,
    Json(body): Json<RoleCreate>,
) -> ApiResult<Created<RoleResponse>> {
    auth::require_admin(&state, &claims).await?;

    let name_len = body.name.chars().count();
    if !(2..=50).contains(&name_len) {
        return Err(validation("name must be 2-50 characters"));
    }
    validate::max_len("description", body.description.as_deref(), 500)?;
    non_negative("max_posts_per_day", Some(body.max_posts_per_day))?;
    non_negative("max_followers", Some(body.max_followers))?;

    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM roles WHERE name = $1)")
        .bind(&body.name)
        .fetch_one(&state.db)
        .await
        .map_err(db_err)?;
    if exists {
        return Err(ApiError::bad_request(format!(
            "Role '{}' already exists",
            body.name
        )));
    }

    let role = sqlx::query_as::<_, RoleRow>(
        "INSERT INTO roles (name, description, can_post, can_comment, can_like, \
         can_delete_own_posts, can_delete_any_posts, can_ban_users, can_verify_users, \
         can_manage_roles, max_posts_per_day, max_followers) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *",
    )
    .bind(&body.name)
    .bind(&body.description)
    .bind(body.can_post)
    .bind(body.can_comment)
    .bind(body.can_like)
    .bind(body.can_delete_own_posts)
    .bind(body.can_delete_any_posts)
    .bind(body.can_ban_users)
    .bind(body.can_verify_users)
    .bind(body.can_manage_roles)
    .bind(body.max_posts_per_day)
    .bind(body.max_followers)
    .fetch_one(&state.db)
    .await
    .map_err(db_err)?;

    Ok(Created(role.into()))
}

/// All roles (public).
#[rustapi_rs::get("/api/v1/roles")]
#[rustapi_rs::tag("Roles")]
#[rustapi_rs::summary("List roles")]
async fn list_roles(State(state): State<AppState>) -> ApiResult<Json<Vec<RoleListItem>>> {
    let roles = sqlx::query_as::<_, RoleRow>("SELECT * FROM roles ORDER BY id")
        .fetch_all(&state.db)
        .await
        .map_err(db_err)?;
    Ok(Json(roles.into_iter().map(Into::into).collect()))
}

#[rustapi_rs::get("/api/v1/roles/{id}")]
#[rustapi_rs::tag("Roles")]
#[rustapi_rs::summary("Get a role")]
async fn get_role(
    State(state): State<AppState>,
    Path(role_id): Path<i64>,
) -> ApiResult<Json<RoleResponse>> {
    let role = db::role_by_id(&state.db, role_id)
        .await?
        .ok_or_else(role_not_found)?;
    Ok(Json(role.into()))
}

/// Change a role's permissions and limits (admin only). Fields you leave out stay as they are.
#[rustapi_rs::put("/api/v1/roles/{id}")]
#[rustapi_rs::tag("Roles")]
#[rustapi_rs::summary("Update a role (admin)")]
async fn update_role(
    State(state): State<AppState>,
    claims: AuthClaims,
    Path(role_id): Path<i64>,
    Json(body): Json<RoleUpdate>,
) -> ApiResult<Json<RoleResponse>> {
    auth::require_admin(&state, &claims).await?;
    validate::max_len("description", body.description.as_deref(), 500)?;
    non_negative("max_posts_per_day", body.max_posts_per_day)?;
    non_negative("max_followers", body.max_followers)?;

    let role = sqlx::query_as::<_, RoleRow>(
        "UPDATE roles SET description = COALESCE($1, description), \
         can_post = COALESCE($2, can_post), can_comment = COALESCE($3, can_comment), \
         can_like = COALESCE($4, can_like), \
         can_delete_own_posts = COALESCE($5, can_delete_own_posts), \
         can_delete_any_posts = COALESCE($6, can_delete_any_posts), \
         can_ban_users = COALESCE($7, can_ban_users), \
         can_verify_users = COALESCE($8, can_verify_users), \
         can_manage_roles = COALESCE($9, can_manage_roles), \
         max_posts_per_day = COALESCE($10, max_posts_per_day), \
         max_followers = COALESCE($11, max_followers), updated_at = now() \
         WHERE id = $12 RETURNING *",
    )
    .bind(&body.description)
    .bind(body.can_post)
    .bind(body.can_comment)
    .bind(body.can_like)
    .bind(body.can_delete_own_posts)
    .bind(body.can_delete_any_posts)
    .bind(body.can_ban_users)
    .bind(body.can_verify_users)
    .bind(body.can_manage_roles)
    .bind(body.max_posts_per_day)
    .bind(body.max_followers)
    .bind(role_id)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?
    .ok_or_else(role_not_found)?;

    Ok(Json(role.into()))
}

/// Delete a role (admin only). Not possible while users still have it.
#[rustapi_rs::delete("/api/v1/roles/{id}")]
#[rustapi_rs::tag("Roles")]
#[rustapi_rs::summary("Delete a role (admin)")]
async fn delete_role(
    State(state): State<AppState>,
    claims: AuthClaims,
    Path(role_id): Path<i64>,
) -> ApiResult<Json<MessageResponse>> {
    auth::require_admin(&state, &claims).await?;

    let role = db::role_by_id(&state.db, role_id)
        .await?
        .ok_or_else(role_not_found)?;
    if role.name == "user" {
        return Err(ApiError::bad_request(
            "The default 'user' role cannot be deleted",
        ));
    }

    let assigned: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role_id = $1")
        .bind(role.id)
        .fetch_one(&state.db)
        .await
        .map_err(db_err)?;
    if assigned > 0 {
        return Err(ApiError::bad_request(
            "Cannot delete role with assigned users",
        ));
    }

    sqlx::query("DELETE FROM roles WHERE id = $1")
        .bind(role.id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;

    Ok(Json(MessageResponse::new(format!(
        "Role '{}' deleted successfully",
        role.name
    ))))
}
