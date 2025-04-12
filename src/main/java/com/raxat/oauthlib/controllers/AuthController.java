package com.raxat.oauthlib.controllers;

import com.raxat.oauthlib.dto.UserDto;
import com.raxat.oauthlib.models.User;
import com.raxat.oauthlib.services.TokenService;
import com.raxat.oauthlib.services.UserService;
import org.antlr.v4.runtime.Token;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController()
@RequestMapping("/api")
public class AuthController {
    @Autowired
    private UserService userService;

    @Autowired
    private TokenService jwtService;

    @Autowired
    private PasswordEncoder passwordEncoder;
    // Логин пользователя и получение JWT токена
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody String username, @RequestBody String password) {
        // Проверка правильности имени пользователя и пароля
        User user = userService.getUserByUsername(username);

        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            return ResponseEntity.badRequest().body("Invalid username or password");
        }

        System.out.println(username);
        // Генерация токена
        String token = jwtService.generateToken(user);
        return ResponseEntity.ok(token); // Отправляем токен
    }

    @PostMapping("/refresh")
    public ResponseEntity<String> refreshToken(@RequestBody Map<String, String> request, @RequestBody String username) {
        String oldToken = request.get("token");
        String newToken = jwtService.refreshToken(oldToken);
        if (!oldToken.equals(newToken)) {
            return ResponseEntity.ok(newToken);
        } else {
            return ResponseEntity.status(400).body("Token is still valid");
        }
    }
}
