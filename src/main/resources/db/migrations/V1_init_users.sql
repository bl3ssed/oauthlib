CREATE TABLE users(
    id bigint generated always as identity primary key,
    username varchar not null unique,
    password varchar not null,
    email varchar not null unique
);

INSERT INTO users (username, password, email)
VALUES ('admin', 'admin', 'admin@admin.com');