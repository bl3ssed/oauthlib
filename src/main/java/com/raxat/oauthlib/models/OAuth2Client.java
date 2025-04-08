package com.raxat.oauthlib.models;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.Id;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Column;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.Set;

@Entity
@Table(name = "oauth2_client")
@Getter
@Setter
public class OAuth2Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String clientId;

    @Column(nullable = false)
    private String clientSecret;

    @Column(name = "redirect_uris", length = 1000)
    private String redirectUris; // CSV или JSON формате

    @Column(length = 500)
    private String scopes; // "openid profile email"

    @Column(length = 500)
    private String grantTypes; // "authorization_code refresh_token"

    @Column(name = "access_token_ttl")
    private Integer accessTokenTTL; // в секундах

    @Column(name = "refresh_token_ttl")
    private Integer refreshTokenTTL; // в секундах

    @Column(name = "created_at")
    private Instant createdAt = Instant.now();

    // Дополнительные поля по необходимости
    private String clientName;
    private String clientDescription;
    private boolean requireProofKey = false;
}