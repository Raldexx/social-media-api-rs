use rustapi_rs::prelude::*;

pub type ApiResult<T> = std::result::Result<T, ApiError>;

/// Turn a database error into an API error. Unique-constraint violations
/// (a race between two requests) become 409, everything else is a 500 that is
/// logged but not shown to the client.
pub fn db_err(e: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(d) = &e {
        if d.code().as_deref() == Some("23505") {
            return ApiError::conflict("Resource already exists");
        }
    }
    tracing::error!("database error: {e}");
    ApiError::internal("Database error")
}

/// 422 - the request body or query is malformed.
pub fn validation(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "validation_error", message)
}

/// 429 - a role limit was reached.
pub fn limit_reached(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::TOO_MANY_REQUESTS, "limit_reached", message)
}
