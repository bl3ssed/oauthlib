package com.raxat.oauthlib.services;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Service;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;

@Service
public class OAuth2FlowService {

    private final OAuth2AuthorizationService authorizationService;

    public OAuth2FlowService(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    /**
     * Создание access_token и refresh_token.
     * Dev2 должен убедиться, что код (authorization_code) валиден.
     */
    public OAuth2AccessTokenResponse generateTokenResponse(String code) {
        OAuth2Authorization authorization = authorizationService.findByToken(code, AUTHORIZATION_CODE);
        if (authorization == null) {
            throw new InvalidGrantException("Invalid authorization code");
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access-token-" + UUID.randomUUID(),
                Instant.now(),
                Instant.now().plus(Duration.ofMinutes(15))  // 15 минут жизни
        );

        return OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
                .tokenType(accessToken.getTokenType())
                .expiresIn(accessToken.getExpiresAt().getEpochSecond())
                .build();
    }
}