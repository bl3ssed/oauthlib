package com.raxat.oauthlib.services;

import com.raxat.oauthlib.exception.ClientValidationException;
import com.raxat.oauthlib.models.OAuth2Client;
import com.raxat.oauthlib.repositories.ClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class OAuth2FlowService {

    private final ClientRepository clientRepository;

    public OAuth2FlowService(ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    public RegisteredClient validateClient(String clientId, String clientSecret) throws ClientValidationException {
        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(clientSecret)) {
            throw new ClientValidationException("Client credentials must not be empty");
        }

        return clientRepository.findByClientId(clientId)
                .filter(client -> validateClientSecret(client, clientSecret))
                .map(this::toRegisteredClient)
                .orElseThrow(() -> new ClientValidationException("Invalid client credentials"));
    }

    private boolean validateClientSecret(OAuth2Client client, String providedSecret) {
        // Здесь должна быть реализация проверки секрета (например, BCrypt)
        return client.getClientSecret().equals(providedSecret); // Временная реализация - замените на безопасную проверку
    }

    private RegisteredClient toRegisteredClient(OAuth2Client client) {
        return RegisteredClient.withId(client.getId().toString())
                .clientId(client.getClientId())
                .clientName(client.getClientName())
                .clientSecret(client.getClientSecret())
                .clientAuthenticationMethods(methods ->
                        methods.addAll(parseAuthenticationMethods(client.getAuthMethods())))
                .authorizationGrantTypes(grants ->
                        grants.addAll(parseGrantTypes(client.getGrantTypes())))
                .redirectUris(uris ->
                        uris.addAll(Collections.singleton(client.getRedirectUris())))
                .scopes(scopes ->
                        scopes.addAll(Collections.singleton(client.getScopes())))
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(client.isRequireProofKey())
                        .requireAuthorizationConsent(client.isRequireConsent())
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(client.getAccessTokenValidity()))
                        .refreshTokenTimeToLive(Duration.ofMinutes(client.getRefreshTokenValidity()))
                        .reuseRefreshTokens(client.isReuseRefreshTokens())
                        .build())
                .build();
    }

    private Set<ClientAuthenticationMethod> parseAuthenticationMethods(String methods) {
        return StringUtils.commaDelimitedListToSet(methods).stream()
                .map(ClientAuthenticationMethod::new)
                .collect(Collectors.toSet());
    }

    private Set<AuthorizationGrantType> parseGrantTypes(String grants) {
        return StringUtils.commaDelimitedListToSet(grants).stream()
                .map(AuthorizationGrantType::new)
                .collect(Collectors.toSet());
    }
}