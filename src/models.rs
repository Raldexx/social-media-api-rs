use chrono::{DateTime, Utc};
use rustapi_rs::prelude::*;
use sqlx::FromRow;

fn ts(d: DateTime<Utc>) -> String {
    d.to_rfc3339()
}

// ---------------------------------------------------------------- DB rows

#[derive(Debug, Clone, FromRow)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub hashed_password: String,
    pub full_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    pub role_id: i64,
    pub role_name: String,
    pub is_active: bool,
    pub is_verified: bool,
    pub is_superuser: bool,
    pub followers_count: i32,
    pub following_count: i32,
    pub posts_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Users are always read together with their role name.
pub const USER_SELECT: &str = "SELECT u.id, u.username, u.email, u.hashed_password, \
    u.full_name, u.bio, u.avatar_url, u.role_id, r.name AS role_name, u.is_active, \
    u.is_verified, u.is_superuser, u.followers_count, u.following_count, u.posts_count, \
    u.created_at, u.updated_at \
    FROM users u JOIN roles r ON r.id = u.role_id";

#[derive(Debug, Clone, FromRow)]
pub struct RoleRow {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub can_post: bool,
    pub can_comment: bool,
    pub can_like: bool,
    pub can_delete_own_posts: bool,
    pub can_delete_any_posts: bool,
    pub can_ban_users: bool,
    pub can_verify_users: bool,
    pub can_manage_roles: bool,
    pub max_posts_per_day: i32,
    pub max_followers: i32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct PostRow {
    pub id: i64,
    pub author_id: i64,
    pub author_username: String,
    pub content: String,
    pub likes_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Posts of deactivated users are hidden.
pub const POST_SELECT: &str = "SELECT p.id, p.author_id, u.username AS author_username, \
    p.content, p.likes_count, p.created_at, p.updated_at \
    FROM posts p JOIN users u ON u.id = p.author_id AND u.is_active";

// -------------------------------------------------------------- responses

#[derive(Debug, Serialize, Schema)]
pub struct MessageResponse {
    pub message: String,
}

impl MessageResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Serialize, Schema)]
pub struct StatsResponse {
    pub followers_count: i32,
    pub following_count: i32,
    pub posts_count: i32,
}

/// Full profile - only for the owner (and admins).
#[derive(Debug, Serialize, Schema)]
pub struct UserResponse {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    pub role: String,
    pub is_active: bool,
    pub is_verified: bool,
    pub is_superuser: bool,
    pub followers_count: i32,
    pub following_count: i32,
    pub posts_count: i32,
    pub created_at: String,
    pub updated_at: String,
}

impl From<UserRow> for UserResponse {
    fn from(u: UserRow) -> Self {
        Self {
            id: u.id,
            username: u.username,
            email: u.email,
            full_name: u.full_name,
            bio: u.bio,
            avatar_url: u.avatar_url,
            role: u.role_name,
            is_active: u.is_active,
            is_verified: u.is_verified,
            is_superuser: u.is_superuser,
            followers_count: u.followers_count,
            following_count: u.following_count,
            posts_count: u.posts_count,
            created_at: ts(u.created_at),
            updated_at: ts(u.updated_at),
        }
    }
}

/// What other people can see (no email).
#[derive(Debug, Serialize, Schema)]
pub struct UserPublicProfile {
    pub id: i64,
    pub username: String,
    pub full_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    pub is_verified: bool,
    pub followers_count: i32,
    pub following_count: i32,
    pub posts_count: i32,
    pub created_at: String,
}

impl From<UserRow> for UserPublicProfile {
    fn from(u: UserRow) -> Self {
        Self {
            id: u.id,
            username: u.username,
            full_name: u.full_name,
            bio: u.bio,
            avatar_url: u.avatar_url,
            is_verified: u.is_verified,
            followers_count: u.followers_count,
            following_count: u.following_count,
            posts_count: u.posts_count,
            created_at: ts(u.created_at),
        }
    }
}

/// Minimal user info for lists (search, followers, following).
#[derive(Debug, Serialize, Schema, FromRow)]
pub struct UserListItem {
    pub id: i64,
    pub username: String,
    pub full_name: Option<String>,
    pub avatar_url: Option<String>,
    pub is_verified: bool,
}

#[derive(Debug, Serialize, Schema)]
pub struct RoleResponse {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub can_post: bool,
    pub can_comment: bool,
    pub can_like: bool,
    pub can_delete_own_posts: bool,
    pub can_delete_any_posts: bool,
    pub can_ban_users: bool,
    pub can_verify_users: bool,
    pub can_manage_roles: bool,
    pub max_posts_per_day: i32,
    pub max_followers: i32,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<RoleRow> for RoleResponse {
    fn from(r: RoleRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            can_post: r.can_post,
            can_comment: r.can_comment,
            can_like: r.can_like,
            can_delete_own_posts: r.can_delete_own_posts,
            can_delete_any_posts: r.can_delete_any_posts,
            can_ban_users: r.can_ban_users,
            can_verify_users: r.can_verify_users,
            can_manage_roles: r.can_manage_roles,
            max_posts_per_day: r.max_posts_per_day,
            max_followers: r.max_followers,
            is_active: r.is_active,
            created_at: ts(r.created_at),
            updated_at: ts(r.updated_at),
        }
    }
}

#[derive(Debug, Serialize, Schema)]
pub struct RoleListItem {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub is_active: bool,
}

impl From<RoleRow> for RoleListItem {
    fn from(r: RoleRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            is_active: r.is_active,
        }
    }
}

#[derive(Debug, Serialize, Schema)]
pub struct PostResponse {
    pub id: i64,
    pub author_id: i64,
    pub author_username: String,
    pub content: String,
    pub likes_count: i32,
    pub created_at: String,
    pub updated_at: String,
}

impl From<PostRow> for PostResponse {
    fn from(p: PostRow) -> Self {
        Self {
            id: p.id,
            author_id: p.author_id,
            author_username: p.author_username,
            content: p.content,
            likes_count: p.likes_count,
            created_at: ts(p.created_at),
            updated_at: ts(p.updated_at),
        }
    }
}

// ------------------------------------------------------------- pagination

#[derive(Debug, Deserialize, Schema)]
pub struct PageQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}
