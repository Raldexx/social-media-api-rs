use rustapi_rs::prelude::*;

use crate::auth::{self, AuthClaims};
use crate::db;
use crate::error::{db_err, ApiResult};
use crate::models::{MessageResponse, PageQuery, UserListItem, UserRow};
use crate::state::AppState;

async fn active_user(state: &AppState, username: &str) -> ApiResult<UserRow> {
    db::user_by_username(&state.db, username)
        .await?
        .filter(|u| u.is_active)
        .ok_or_else(|| ApiError::not_found("User not found"))
}

/// Follow a user. The followed user's role decides how many followers they may have.
#[rustapi_rs::post("/api/v1/users/{key}/follow")]
#[rustapi_rs::tag("Follows")]
#[rustapi_rs::summary("Follow a user")]
async fn follow_user(
    State(state): State<AppState>,
    claims: AuthClaims,
    Path(username): Path<String>,
) -> ApiResult<Json<MessageResponse>> {
    let me = auth::current_user(&state, &claims).await?;
    let target = active_user(&state, &username).await?;
    if target.id == me.id {
        return Err(ApiError::bad_request("You cannot follow yourself"));
    }

    let target_role = auth::role_of(&state, &target).await?;
    if !target.is_superuser && target.followers_count >= target_role.max_followers {
        return Err(ApiError::forbidden(
            "This user has reached the maximum number of followers",
        ));
    }

    let mut tx = state.db.begin().await.map_err(db_err)?;
    let inserted = sqlx::query(
        "INSERT INTO follows (follower_id, following_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(me.id)
    .bind(target.id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict("Already following this user"));
    }
    // One statement for both counters (avoids two requests locking the rows in opposite order).
    sqlx::query(
        "UPDATE users SET \
         followers_count = followers_count + CASE WHEN id = $2 THEN 1 ELSE 0 END, \
         following_count = following_count + CASE WHEN id = $1 THEN 1 ELSE 0 END \
         WHERE id IN ($1, $2)",
    )
    .bind(me.id)
    .bind(target.id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    Ok(Json(MessageResponse::new(format!(
        "You are now following {}",
        target.username
    ))))
}

#[rustapi_rs::delete("/api/v1/users/{key}/follow")]
#[rustapi_rs::tag("Follows")]
#[rustapi_rs::summary("Unfollow a user")]
async fn unfollow_user(
    State(state): State<AppState>,
    claims: AuthClaims,
    Path(username): Path<String>,
) -> ApiResult<Json<MessageResponse>> {
    let me = auth::current_user(&state, &claims).await?;
    let target = db::user_by_username(&state.db, &username)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;

    let mut tx = state.db.begin().await.map_err(db_err)?;
    let removed = sqlx::query("DELETE FROM follows WHERE follower_id = $1 AND following_id = $2")
        .bind(me.id)
        .bind(target.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    if removed.rows_affected() == 0 {
        return Err(ApiError::not_found("You are not following this user"));
    }
    sqlx::query(
        "UPDATE users SET \
         followers_count = GREATEST(followers_count - CASE WHEN id = $2 THEN 1 ELSE 0 END, 0), \
         following_count = GREATEST(following_count - CASE WHEN id = $1 THEN 1 ELSE 0 END, 0) \
         WHERE id IN ($1, $2)",
    )
    .bind(me.id)
    .bind(target.id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    Ok(Json(MessageResponse::new(format!(
        "You unfollowed {}",
        target.username
    ))))
}

/// People who follow this user (public).
#[rustapi_rs::get("/api/v1/users/{key}/followers")]
#[rustapi_rs::tag("Follows")]
#[rustapi_rs::summary("List a user's followers")]
async fn list_followers(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(params): Query<PageQuery>,
) -> ApiResult<Json<Vec<UserListItem>>> {
    let (limit, offset) = db::page(&state.config, &params)?;
    let target = active_user(&state, &username).await?;
    let users = sqlx::query_as::<_, UserListItem>(
        "SELECT u.id, u.username, u.full_name, u.avatar_url, u.is_verified \
         FROM follows f JOIN users u ON u.id = f.follower_id AND u.is_active \
         WHERE f.following_id = $1 ORDER BY f.created_at DESC, u.id LIMIT $2 OFFSET $3",
    )
    .bind(target.id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;
    Ok(Json(users))
}

/// People this user follows (public).
#[rustapi_rs::get("/api/v1/users/{key}/following")]
#[rustapi_rs::tag("Follows")]
#[rustapi_rs::summary("List who a user follows")]
async fn list_following(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(params): Query<PageQuery>,
) -> ApiResult<Json<Vec<UserListItem>>> {
    let (limit, offset) = db::page(&state.config, &params)?;
    let target = active_user(&state, &username).await?;
    let users = sqlx::query_as::<_, UserListItem>(
        "SELECT u.id, u.username, u.full_name, u.avatar_url, u.is_verified \
         FROM follows f JOIN users u ON u.id = f.following_id AND u.is_active \
         WHERE f.follower_id = $1 ORDER BY f.created_at DESC, u.id LIMIT $2 OFFSET $3",
    )
    .bind(target.id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;
    Ok(Json(users))
}
