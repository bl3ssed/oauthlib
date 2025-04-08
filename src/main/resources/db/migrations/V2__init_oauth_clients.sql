CREATE TABLE oauth2_client (
                               id BIGINT PRIMARY KEY AUTO_INCREMENT,
                               client_id VARCHAR(255) NOT NULL UNIQUE,
                               client_secret VARCHAR(255) NOT NULL,
                               redirect_uris TEXT,
                               scopes VARCHAR(255),
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO oauth2_client (client_id, client_secret, redirect_uris, scopes)
VALUES ('test-client', 'secret', 'http://localhost:8080/callback', 'openid profile');