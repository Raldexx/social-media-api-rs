use rustapi_rs::prelude::*;
use sqlx::PgPool;

use crate::auth::{self, allowed, AuthClaims};
use crate::db;
use crate::error::{db_err, limit_reached, validation, ApiResult};
use crate::models::{MessageResponse, PageQuery, PostResponse, PostRow, POST_SELECT};
use crate::state::AppState;

#[derive(Debug, Deserialize, Schema)]
pub struct PostCreate {
    pub content: String,
}

async fn post_by_id(db: &PgPool, id: i64) -> ApiResult<PostRow> {
    sqlx::query_as::<_, PostRow>(&format!("{POST_SELECT} WHERE p.id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(db_err)?
        .ok_or_else(|| ApiError::not_found("Post not found"))
}

/// Write a post. Needs a role with `can_post`, and the role's
/// `max_posts_per_day` (counted over the last 24 hours) must not be used up.
#[rustapi_rs::post("/api/v1/posts")]
#[rustapi_rs::tag("Posts")]
#[rustapi_rs::summary("Create a post")]
async fn create_post(
    State(state): State<AppState>,
    claims: AuthClaims,
    Json(body): Json<PostCreate>,
) -> ApiResult<Created<PostResponse>> {
    let user = auth::current_user(&state, &claims).await?;
    let role = auth::role_of(&state, &user).await?;

    let content = body.content.trim().to_string();
    if content.is_empty() || content.chars().count() > 1000 {
        return Err(validation("content must be 1-1000 characters"));
    }
    if !allowed(&user, &role, |r| r.can_post) {
        return Err(ApiError::forbidden("Your role is not allowed to create posts"));
    }

    let mut tx = state.db.begin().await.map_err(db_err)?;

    // Lock the user's row so two simultaneous posts cannot both slip under the limit.
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

    if !user.is_superuser {
        let used: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM posts \
             WHERE author_id = $1 AND created_at > now() - interval '24 hours'",
        )
        .bind(user.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        if used >= i64::from(role.max_posts_per_day) {
            return Err(limit_reached("Daily post limit reached for your role"));
        }
    }

    let id: i64 =
        sqlx::query_scalar("INSERT INTO posts (author_id, content) VALUES ($1, $2) RETURNING id")
            .bind(user.id)
            .bind(&content)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;

    sqlx::query("UPDATE users SET posts_count = posts_count + 1 WHERE id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

    tx.commit().await.map_err(db_err)?;

    Ok(Created(post_by_id(&state.db, id).await?.into()))
}

/// Newest posts first (public). Use `?limit=&offset=` to page.
#[rustapi_rs::get("/api/v1/posts")]
#[rustapi_rs::tag("Posts")]
#[rustapi_rs::summary("List posts")]
async fn list_posts(
    State(state): State<AppState>,
    Query(params): Query<PageQuery>,
) -> ApiResult<Json<Vec<PostResponse>>> {
    let (limit, offset) = db::page(&state.config, &params)?;
    let posts = sqlx::query_as::<_, PostRow>(&format!(
        "{POST_SELECT} ORDER BY p.created_at DESC, p.id DESC LIMIT $1 OFFSET $2"
    ))
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;
    Ok(Json(posts.into_iter().map(Into::into).collect()))
}

/// Posts of one user, newest first (public).
#[rustapi_rs::get("/api/v1/users/{key}/posts")]
#[rustapi_rs::tag("Posts")]
#[rustapi_rs::summary("List a user's posts")]
async fn list_user_posts(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(params): Query<PageQuery>,
) -> ApiResult<Json<Vec<PostResponse>>> {
    let (limit, offset) = db::page(&state.config, &params)?;
    let user = db::user_by_username(&state.db, &username)
        .await?
        .filter(|u| u.is_active)
        .ok_or_else(|| ApiError::not_found("User not found"))?;

    let posts = sqlx::query_as::<_, PostRow>(&format!(
        "{POST_SELECT} WHERE p.author_id = $1 \
         ORDER BY p.created_at DESC, p.id DESC LIMIT $2 OFFSET $3"
    ))
    .bind(user.id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;
    Ok(Json(posts.into_iter().map(Into::into).collect()))
}

#[rustapi_rs::get("/api/v1/posts/{id}")]
#[rustapi_rs::tag("Posts")]
#[rustapi_rs::summary("Get a post")]
async fn get_post(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<PostResponse>> {
    Ok(Json(post_by_id(&state.db, id).await?.into()))
}

/// Delete a post. Your own: needs `can_delete_own_posts`. Someone else's: needs `can_delete_any_posts`.
#[rustapi_rs::delete("/api/v1/posts/{id}")]
#[rustapi_rs::tag("Posts")]
#[rustapi_rs::summary("Delete a post")]
async fn delete_post(
    State(state): State<AppState>,
    claims: AuthClaims,
    Path(id): Path<i64>,
) -> ApiResult<Json<MessageResponse>> {
    let user = auth::current_user(&state, &claims).await?;
    let role = auth::role_of(&state, &user).await?;
    let post = post_by_id(&state.db, id).await?;

    let permitted = if post.author_id == user.id {
        allowed(&user, &role, |r| r.can_delete_own_posts)
    } else {
        allowed(&user, &role, |r| r.can_delete_any_posts)
    };
    if !permitted {
        return Err(ApiError::forbidden(
            "Your role is not allowed to delete this post",
        ));
    }

    let mut tx = state.db.begin().await.map_err(db_err)?;
    let deleted = sqlx::query("DELETE FROM posts WHERE id = $1")
        .bind(post.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::not_found("Post not found"));
    }
    sqlx::query("UPDATE users SET posts_count = GREATEST(posts_count - 1, 0) WHERE id = $1")
        .bind(post.author_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    Ok(Json(MessageResponse::new("Post deleted successfully")))
}

/// Like a post. Needs a role with `can_like`.
#[rustapi_rs::post("/api/v1/posts/{id}/like")]
#[rustapi_rs::tag("Posts")]
#[rustapi_rs::summary("Like a post")]
async fn like_post(
    State(state): State<AppState>,
    claims: AuthClaims,
    Path(id): Path<i64>,
) -> ApiResult<Json<PostResponse>> {
    let user = auth::current_user(&state, &claims).await?;
    let role = auth::role_of(&state, &user).await?;
    if !allowed(&user, &role, |r| r.can_like) {
        return Err(ApiError::forbidden("Your role is not allowed to like posts"));
    }
    let post = post_by_id(&state.db, id).await?;

    let mut tx = state.db.begin().await.map_err(db_err)?;
    let inserted = sqlx::query(
        "INSERT INTO likes (user_id, post_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(user.id)
    .bind(post.id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict("Post already liked"));
    }
    sqlx::query("UPDATE posts SET likes_count = likes_count + 1 WHERE id = $1")
        .bind(post.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    Ok(Json(post_by_id(&state.db, post.id).await?.into()))
}

#[rustapi_rs::delete("/api/v1/posts/{id}/like")]
#[rustapi_rs::tag("Posts")]
#[rustapi_rs::summary("Remove my like from a post")]
async fn unlike_post(
    State(state): State<AppState>,
    claims: AuthClaims,
    Path(id): Path<i64>,
) -> ApiResult<Json<PostResponse>> {
    let user = auth::current_user(&state, &claims).await?;
    let post = post_by_id(&state.db, id).await?;

    let mut tx = state.db.begin().await.map_err(db_err)?;
    let removed = sqlx::query("DELETE FROM likes WHERE user_id = $1 AND post_id = $2")
        .bind(user.id)
        .bind(post.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    if removed.rows_affected() == 0 {
        return Err(ApiError::not_found("Like not found"));
    }
    sqlx::query("UPDATE posts SET likes_count = GREATEST(likes_count - 1, 0) WHERE id = $1")
        .bind(post.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    Ok(Json(post_by_id(&state.db, post.id).await?.into()))
}
