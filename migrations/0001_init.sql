-- Roles: permissions and limits. Every user has exactly one role.
CREATE TABLE roles (
    id                    BIGSERIAL PRIMARY KEY,
    name                  VARCHAR(50) NOT NULL UNIQUE,
    description           TEXT,
    can_post              BOOLEAN NOT NULL DEFAULT TRUE,
    can_comment           BOOLEAN NOT NULL DEFAULT TRUE,
    can_like              BOOLEAN NOT NULL DEFAULT TRUE,
    can_delete_own_posts  BOOLEAN NOT NULL DEFAULT TRUE,
    can_delete_any_posts  BOOLEAN NOT NULL DEFAULT FALSE,
    can_ban_users         BOOLEAN NOT NULL DEFAULT FALSE,
    can_verify_users      BOOLEAN NOT NULL DEFAULT FALSE,
    can_manage_roles      BOOLEAN NOT NULL DEFAULT FALSE,
    max_posts_per_day     INTEGER NOT NULL DEFAULT 100 CHECK (max_posts_per_day >= 0),
    max_followers         INTEGER NOT NULL DEFAULT 10000 CHECK (max_followers >= 0),
    is_active             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Default role given to every new user.
INSERT INTO roles (name, description) VALUES ('user', 'Default role for new users');

CREATE TABLE users (
    id               BIGSERIAL PRIMARY KEY,
    username         VARCHAR(50)  NOT NULL UNIQUE,
    email            VARCHAR(100) NOT NULL UNIQUE,
    hashed_password  VARCHAR(255) NOT NULL,
    full_name        VARCHAR(100),
    bio              VARCHAR(500),
    avatar_url       VARCHAR(255),
    role_id          BIGINT NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    is_active        BOOLEAN NOT NULL DEFAULT TRUE,
    is_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    is_superuser     BOOLEAN NOT NULL DEFAULT FALSE,
    followers_count  INTEGER NOT NULL DEFAULT 0,
    following_count  INTEGER NOT NULL DEFAULT 0,
    posts_count      INTEGER NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX users_role_id_idx ON users (role_id);

CREATE TABLE posts (
    id           BIGSERIAL PRIMARY KEY,
    author_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content      TEXT NOT NULL CHECK (char_length(content) BETWEEN 1 AND 1000),
    likes_count  INTEGER NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX posts_author_created_idx ON posts (author_id, created_at DESC);
CREATE INDEX posts_created_idx ON posts (created_at DESC);

CREATE TABLE likes (
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    post_id     BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, post_id)
);

CREATE TABLE follows (
    follower_id   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    following_id  BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (follower_id, following_id),
    CHECK (follower_id <> following_id)
);
CREATE INDEX follows_following_idx ON follows (following_id, created_at DESC);
