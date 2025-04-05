package com.raxat.oauthlib.controllers;


import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class UserInfoController {

    /**
     * Эндпоинт /userinfo (OIDC-стандарт).
     * Возвращает claims из JWT (sub, email, roles).
     */
    @GetMapping("/userinfo")
    public Map<String, Object> getUserInfo(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "sub", jwt.getSubject(),          // Идентификатор пользователя
                "email", jwt.getClaim("email"),   // Email (если есть в токене)
                "roles", jwt.getClaim("roles")    // Роли пользователя
        );
    }
}