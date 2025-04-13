package com.raxat.oauthlib.services;

import com.raxat.oauthlib.exception.ClientValidationException;
import com.raxat.oauthlib.models.OAuth2Client;
import com.raxat.oauthlib.repositories.ClientRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.StringUtils;

import java.lang.reflect.Method;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OAuth2FlowServiceTest {

    @Mock
    private ClientRepository clientRepository;

    @InjectMocks
    private OAuth2FlowService oAuth2FlowService;

    private OAuth2Client testClient;
    private final String CLIENT_ID = "test-client";
    private final String CLIENT_SECRET = "test-secret";
    private final String REDIRECT_URI = "http://localhost:8080/callback";
    private final String SCOPES = "read,write";
    private final String GRANT_TYPES = "authorization_code,refresh_token";
    private final String AUTH_METHODS = "client_secret_basic";

    @BeforeEach
    void setUp() {
        testClient = new OAuth2Client();
        testClient.setId(1L); // Изменено с UUID на Long
        testClient.setClientId(CLIENT_ID);
        testClient.setClientSecret(CLIENT_SECRET);
        testClient.setClientName("Test Client");
        testClient.setRedirectUris(REDIRECT_URI);
        testClient.setScopes(SCOPES);
        testClient.setGrantTypes(GRANT_TYPES);
        testClient.setAuthMethods(AUTH_METHODS);
        testClient.setRequireProofKey(true);
        testClient.setRequireAuthorizationConsent(true); // Изменено с setRequireConsent
        testClient.setAccessTokenTTL(3600); // В секундах (60 минут)
        testClient.setRefreshTokenTTL(86400); // В секундах (1440 минут)
        testClient.setReuseRefreshTokens(true);
    }

    @Test
    void validateClient_Success() throws ClientValidationException {
        when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(testClient));

        RegisteredClient result = oAuth2FlowService.validateClient(CLIENT_ID, CLIENT_SECRET);

        assertNotNull(result);
        assertEquals(CLIENT_ID, result.getClientId());
        assertEquals(testClient.getClientName(), result.getClientName());
        assertEquals(CLIENT_SECRET, result.getClientSecret());
        assertEquals(REDIRECT_URI, result.getRedirectUris().iterator().next());
        assertTrue(result.getScopes().containsAll(StringUtils.commaDelimitedListToSet(SCOPES.replace(" ", ","))));

        verify(clientRepository, times(1)).findByClientId(CLIENT_ID);
    }

    @Test
    void validateClient_EmptyCredentials_ThrowsException() {
        assertThrows(ClientValidationException.class,
                () -> oAuth2FlowService.validateClient("", ""));
        assertThrows(ClientValidationException.class,
                () -> oAuth2FlowService.validateClient(CLIENT_ID, ""));
        assertThrows(ClientValidationException.class,
                () -> oAuth2FlowService.validateClient("", CLIENT_SECRET));

        verify(clientRepository, never()).findByClientId(anyString());
    }

    @Test
    void validateClient_InvalidClientId_ThrowsException() {
        when(clientRepository.findByClientId("invalid-client")).thenReturn(Optional.empty());

        assertThrows(ClientValidationException.class,
                () -> oAuth2FlowService.validateClient("invalid-client", CLIENT_SECRET));

        verify(clientRepository, times(1)).findByClientId("invalid-client");
    }

    @Test
    void validateClient_InvalidClientSecret_ThrowsException() {
        when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(testClient));

        assertThrows(ClientValidationException.class,
                () -> oAuth2FlowService.validateClient(CLIENT_ID, "wrong-secret"));

        verify(clientRepository, times(1)).findByClientId(CLIENT_ID);
    }

    @Test
    void toRegisteredClient_ConversionCorrect() throws Exception {
        Method method = OAuth2FlowService.class.getDeclaredMethod("toRegisteredClient", OAuth2Client.class);
        method.setAccessible(true);
        RegisteredClient registeredClient = (RegisteredClient) method.invoke(oAuth2FlowService, testClient);

        // Verify basic fields
        assertEquals(testClient.getId().toString(), registeredClient.getId());
        assertEquals(CLIENT_ID, registeredClient.getClientId());
        assertEquals(testClient.getClientName(), registeredClient.getClientName());
        assertEquals(CLIENT_SECRET, registeredClient.getClientSecret());

        // Verify authentication methods
        Set<ClientAuthenticationMethod> expectedAuthMethods =
                Set.of(new ClientAuthenticationMethod("client_secret_basic"));
        assertEquals(expectedAuthMethods, registeredClient.getClientAuthenticationMethods());

        // Verify grant types
        Set<AuthorizationGrantType> expectedGrantTypes =
                Set.of(new AuthorizationGrantType("authorization_code"),
                        new AuthorizationGrantType("refresh_token"));
        assertEquals(expectedGrantTypes, registeredClient.getAuthorizationGrantTypes());

        // Verify client settings
        ClientSettings clientSettings = registeredClient.getClientSettings();
        assertTrue(clientSettings.isRequireProofKey());
        assertTrue(clientSettings.isRequireAuthorizationConsent());

        // Verify token settings
        TokenSettings tokenSettings = registeredClient.getTokenSettings();
        assertEquals(Duration.ofMinutes(60), tokenSettings.getAccessTokenTimeToLive());
        assertEquals(Duration.ofMinutes(1440), tokenSettings.getRefreshTokenTimeToLive());
        assertTrue(tokenSettings.isReuseRefreshTokens());
    }

    @Test
    void parseAuthenticationMethods_ParsingCorrect() throws Exception {
        Method method = OAuth2FlowService.class.getDeclaredMethod("parseAuthenticationMethods", String.class);
        method.setAccessible(true);

        Set<ClientAuthenticationMethod> result = (Set<ClientAuthenticationMethod>)
                method.invoke(oAuth2FlowService, "client_secret_basic,client_secret_post");

        assertEquals(2, result.size());
        assertTrue(result.contains(new ClientAuthenticationMethod("client_secret_basic")));
        assertTrue(result.contains(new ClientAuthenticationMethod("client_secret_post")));
    }

    @Test
    void parseGrantTypes_ParsingCorrect() throws Exception {
        // Получаем приватный метод через рефлексию
        Method method = OAuth2FlowService.class.getDeclaredMethod("parseGrantTypes", String.class);
        method.setAccessible(true); // Делаем доступным

        String grants = "authorization_code,refresh_token,client_credentials";

        // Вызываем метод
        @SuppressWarnings("unchecked")
        Set<AuthorizationGrantType> result = (Set<AuthorizationGrantType>)
                method.invoke(oAuth2FlowService, grants);

        // Проверки
        assertEquals(3, result.size());
        assertTrue(result.contains(new AuthorizationGrantType("authorization_code")));
        assertTrue(result.contains(new AuthorizationGrantType("refresh_token")));
        assertTrue(result.contains(new AuthorizationGrantType("client_credentials")));
    }
}
