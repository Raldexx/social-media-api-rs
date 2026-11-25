// Every handler registers itself through its `#[rustapi_rs::get/post/...]`
// attribute, so these modules only have to be compiled in.
pub mod auth;
pub mod follows;
pub mod posts;
pub mod roles;
pub mod users;
