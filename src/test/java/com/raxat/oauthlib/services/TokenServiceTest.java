package com.raxat.oauthlib.services;

import com.raxat.oauthlib.models.JwtToken;
import com.raxat.oauthlib.models.User;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.Field;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TokenServiceTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private TokenService tokenService;

    private User testUser;

    @BeforeEach
    void setUp() throws NoSuchFieldException, IllegalAccessException {
        MockitoAnnotations.openMocks(this);

        var secret = tokenService.getClass().getDeclaredField("secret");
        secret.setAccessible(true);
        secret.set(tokenService, "supersecretkeysupersecretkey123456");

        var expirationMs = tokenService.getClass().getDeclaredField("expirationMs");
        expirationMs.setAccessible(true);
        expirationMs.set(tokenService, 1000 * 60 * 10);

        var expirationMsRefresh = tokenService.getClass().getDeclaredField("expirationMsRefresh");
        expirationMsRefresh.setAccessible(true);
        expirationMsRefresh.set(tokenService, 1000 * 60 * 60 * 24);

        testUser = new User();
        testUser.setUsername("john_doe");
        testUser.setEmail("john@example.com");
        testUser.setPassword("encoded_password");
    }

    @Test
    void testGenerateTokenReturnsNonNullTokens() {
        JwtToken token = tokenService.generateToken(testUser);

        assertNotNull(token);
        assertNotNull(token.getToken());
        assertNotNull(token.getRefreshToken());
    }

    @Test
    void testExtractUsernameReturnsCorrectUsername() {
        JwtToken token = tokenService.generateToken(testUser);
        String username = tokenService.extractUsername(token.getToken());

        assertEquals("john_doe", username);
    }

    @Test
    void testIsTokenExpiredReturnsFalseForValidToken() {
        JwtToken token = tokenService.generateToken(testUser);
        assertFalse(tokenService.isTokenExpired(token.getToken()));
    }

    @Test
    void testValidateTokenReturnsTrueForValidToken() {
        JwtToken token = tokenService.generateToken(testUser);
        assertTrue(tokenService.validateToken(token.getToken()));
    }

    @Test
    void testRefreshTokenReturnsSameTokenIfNotExpired() {
        JwtToken originalToken = tokenService.generateToken(testUser);
        JwtToken refreshed = tokenService.refreshToken(originalToken);

        assertEquals(originalToken.getToken(), refreshed.getToken());
        assertEquals(originalToken.getRefreshToken(), refreshed.getRefreshToken());
    }

    @Test
    void testRefreshTokenGeneratesNewTokenWhenAccessTokenExpired() throws InterruptedException, NoSuchFieldException, IllegalAccessException {
        // Установим короткое время жизни токена вручную
        Field expirationMsField = TokenService.class.getDeclaredField("expirationMs");
        expirationMsField.setAccessible(true);
        expirationMsField.set(tokenService, 1000L); // 1 секунда

        JwtToken expiredToken = tokenService.generateToken(testUser);

        // Ждём, чтобы токен точно успел протухнуть
        Thread.sleep(1500);

        // Возвращаем пользователя
        when(userService.getUserByUsername("john_doe")).thenReturn(testUser);

        // Теперь вызываем refresh
        JwtToken refreshed = tokenService.refreshToken(expiredToken);

        // Проверяем, что refresh сработал — получили новый токен
        assertNotEquals(expiredToken.getToken(), refreshed.getToken());
        assertNotNull(refreshed.getToken());
        assertNotNull(refreshed.getRefreshToken());
    }
}