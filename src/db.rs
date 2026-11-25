use sqlx::PgPool;

use crate::error::{db_err, validation, ApiResult};
use crate::config::Config;
use crate::models::{PageQuery, RoleRow, UserRow, USER_SELECT};

pub async fn user_by_id(db: &PgPool, id: i64) -> ApiResult<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>(&format!("{USER_SELECT} WHERE u.id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(db_err)
}

pub async fn user_by_username(db: &PgPool, username: &str) -> ApiResult<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>(&format!("{USER_SELECT} WHERE u.username = $1"))
        .bind(username.to_lowercase())
        .fetch_optional(db)
        .await
        .map_err(db_err)
}

pub async fn user_by_email(db: &PgPool, email: &str) -> ApiResult<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>(&format!("{USER_SELECT} WHERE u.email = $1"))
        .bind(email)
        .fetch_optional(db)
        .await
        .map_err(db_err)
}

pub async fn role_by_id(db: &PgPool, id: i64) -> ApiResult<Option<RoleRow>> {
    sqlx::query_as::<_, RoleRow>("SELECT * FROM roles WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(db_err)
}

/// Resolve `?limit=&offset=` into validated numbers.
pub fn page(config: &Config, q: &PageQuery) -> ApiResult<(i64, i64)> {
    let limit = q.limit.unwrap_or(config.default_page_size);
    if !(1..=config.max_page_size).contains(&limit) {
        return Err(validation(format!(
            "limit must be between 1 and {}",
            config.max_page_size
        )));
    }
    let offset = q.offset.unwrap_or(0);
    if offset < 0 {
        return Err(validation("offset must be 0 or greater"));
    }
    Ok((limit, offset))
}
