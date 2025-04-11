package com.raxat.oauthlib.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

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
    private String redirectUris;

    @Column(length = 500)
    private String scopes;

    @Column(length = 500)
    private String grantTypes;

    @Column(length = 500)
    private String authMethods = "client_secret_basic";

    @Column(name = "access_token_ttl")
    private Integer accessTokenTTL = 3600; // В секундах

    @Column(name = "refresh_token_ttl")
    private Integer refreshTokenTTL = 86400; // В секундах

    @Column(name = "created_at")
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at")
    private Instant updatedAt = Instant.now();

    // Дополнительные поля
    private String clientName;
    private String clientDescription;
    private boolean requireProofKey = false;
    private boolean requireAuthorizationConsent = true;
    private boolean reuseRefreshTokens = true;

    // Методы, которые ожидает OAuth2FlowService

    public boolean isRequireConsent() {
        return requireAuthorizationConsent;
    }

    public int getAccessTokenValidity() {
        return accessTokenTTL != null ? accessTokenTTL / 60 : 60; // Конвертация в минуты
    }

    public int getRefreshTokenValidity() {
        return refreshTokenTTL != null ? refreshTokenTTL / 60 : 1440; // Конвертация в минуты
    }

    public boolean isReuseRefreshTokens() {
        return reuseRefreshTokens;
    }

    // Вспомогательные методы для работы с коллекциями

    public Set<String> getRedirectUrisSet() {
        return redirectUris == null ? Collections.emptySet() :
                Arrays.stream(redirectUris.split(","))
                        .map(String::trim)
                        .collect(Collectors.toSet());
    }

    public Set<String> getScopesSet() {
        return scopes == null ? Collections.emptySet() :
                Arrays.stream(scopes.split(" "))
                        .map(String::trim)
                        .collect(Collectors.toSet());
    }

    public Set<AuthorizationGrantType> getGrantTypesSet() {
        return grantTypes == null ? Collections.emptySet() :
                Arrays.stream(grantTypes.split(","))
                        .map(String::trim)
                        .map(AuthorizationGrantType::new)
                        .collect(Collectors.toSet());
    }

    public Set<ClientAuthenticationMethod> getAuthMethodsSet() {
        return authMethods == null ? Set.of(new ClientAuthenticationMethod("client_secret_basic")) :
                Arrays.stream(authMethods.split(","))
                        .map(String::trim)
                        .map(ClientAuthenticationMethod::new)
                        .collect(Collectors.toSet());
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = Instant.now();
    }
}