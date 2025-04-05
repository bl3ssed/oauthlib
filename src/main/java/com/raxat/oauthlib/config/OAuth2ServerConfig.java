package com.raxat.oauthlib.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import java.util.UUID;

@Configuration
public class OAuth2ServerConfig {

    /**
     * Регистрация клиентов OAuth2 (в памяти или БД).
     * Здесь Dev2 определяет, какие приложения могут использовать микросервис.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient webClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("webapp")  // Идентификатор клиента
                .clientSecret("{bcrypt}$2a$10$XZlw9gZb4PZbBTeqNwvJKeYv6w6cQ6X9z8dZwK9LkRt1JzQ1Y6JZa")  // Хэшированный секрет
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)  // Способ аутентификации
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)  // Разрешенный grant type
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://myapp.com/callback")  // Разрешенный redirect_uri
                .scope(OidcScopes.OPENID)  // Запрашиваемые scope (openid для OIDC)
                .scope("read")  // Кастомные scope
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())  // Включение PKCE
                .build();

        return new InMemoryRegisteredClientRepository(webClient);
    }

    /**
     * Настройки сервера (issuer, URL эндпоинтов).
     * issuer должен совпадать с iss в JWT.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://auth-service:8080")  // URL вашего сервиса
                .build();
    }
}