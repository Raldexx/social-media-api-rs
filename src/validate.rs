use crate::error::{validation, ApiResult};

/// 3-50 chars, letters/digits/underscore. Returns the lowercase form.
pub fn username(v: &str) -> ApiResult<String> {
    let n = v.chars().count();
    if !(3..=50).contains(&n) {
        return Err(validation("username must be 3-50 characters"));
    }
    if !v.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(validation(
            "username must contain only letters, numbers and underscore",
        ));
    }
    Ok(v.to_lowercase())
}

/// Simple shape check: `name@domain.tld`, no spaces, at most 100 chars.
pub fn email(v: &str) -> ApiResult<()> {
    let ok = v.chars().count() <= 100
        && !v.contains(char::is_whitespace)
        && match v.split_once('@') {
            Some((local, domain)) => {
                !local.is_empty()
                    && !domain.contains('@')
                    && domain.contains('.')
                    && !domain.starts_with('.')
                    && !domain.ends_with('.')
            }
            None => false,
        };
    if ok {
        Ok(())
    } else {
        Err(validation("email is not a valid email address"))
    }
}

/// 8-100 chars with an uppercase letter, a lowercase letter and a digit.
pub fn password(v: &str) -> ApiResult<()> {
    let n = v.chars().count();
    if !(8..=100).contains(&n) {
        return Err(validation("password must be 8-100 characters"));
    }
    if !v.chars().any(|c| c.is_uppercase()) {
        return Err(validation("Password must contain at least one uppercase letter"));
    }
    if !v.chars().any(|c| c.is_lowercase()) {
        return Err(validation("Password must contain at least one lowercase letter"));
    }
    if !v.chars().any(|c| c.is_ascii_digit()) {
        return Err(validation("Password must contain at least one digit"));
    }
    Ok(())
}

/// Optional text field with a maximum length.
pub fn max_len(field: &str, v: Option<&str>, max: usize) -> ApiResult<()> {
    match v {
        Some(s) if s.chars().count() > max => {
            Err(validation(format!("{field} must be at most {max} characters")))
        }
        _ => Ok(()),
    }
}
