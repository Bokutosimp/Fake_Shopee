-- ShopStack schema + seed data.
-- The admin password is injected at build/seed time as a long random value and is
-- NEVER needed to solve the challenge (Stage 1 SQLi bypasses auth entirely).
-- No default or guessable credentials exist. See entrypoint.sh for password gen.

DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0
);

-- Admin row. Password placeholder is replaced with a random secret at seed time.
INSERT INTO users (username, password, is_admin) VALUES ('admin', '__ADMIN_PASSWORD__', 1);

-- A non-admin decoy account, also with a random password. Not an intended path.
INSERT INTO users (username, password, is_admin) VALUES ('customer', '__CUSTOMER_PASSWORD__', 0);
