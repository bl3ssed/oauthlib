package com.raxat.oauthlib.controllers;

import com.raxat.oauthlib.dto.AuthRequest;
import com.raxat.oauthlib.models.JwtToken;
import com.raxat.oauthlib.models.User;
import com.raxat.oauthlib.services.TokenService;
import com.raxat.oauthlib.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


@RestController()
@RequestMapping("/api")
public class AuthController {
    @Autowired
    private UserService userService;

    @Autowired
    private TokenService jwtService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Выполняет вход пользователя в систему.
     * <p>
     * Проверяет, существует ли пользователь с указанным именем, и совпадает ли его пароль.
     * В случае успешной проверки генерирует и возвращает access и refresh токены.
     *
     * @param requestedUser Объект с username и password.
     * @return 200 OK с JWT токенами в теле ответа, если авторизация успешна;
     *         400 Bad Request, если имя пользователя не найдено или пароль неверен.
     */
    @PostMapping("/login")
    public ResponseEntity<JwtToken> login(@RequestBody AuthRequest requestedUser) {
        User user = userService.getUserByUsername(requestedUser.username());

        if (user == null || !passwordEncoder.matches(requestedUser.password(), user.getPassword())) {
            return ResponseEntity.badRequest().body(null);
        }

        JwtToken token = jwtService.generateToken(user);
        return ResponseEntity.ok(token);
    }

    /**
     * Обновляет access токен с помощью refresh токена.
     * <p>
     * Принимает токен, проверяет его валидность и выдает новый access/refresh токен, если время жизни access токена прошло.
     *
     * @param token    Объект {@link JwtToken}, содержащий текущие access и refresh токены.
     * @param username Имя пользователя, которому принадлежит токен.
     * @return 200 OK с новым JWT токеном в теле ответа.
     */
    @PostMapping("/refresh")
    public ResponseEntity<JwtToken> refreshToken(@RequestBody JwtToken token, @RequestBody String username) {
        JwtToken newToken = jwtService.refreshToken(token);
        return ResponseEntity.ok(newToken);
    }

    /**
     * Выполняет выход пользователя из системы.
     * <p>
     * Очищает контекст безопасности Spring Security.
     * Это будет означать, что текущий пользователь больше не будет аутентифицирован в приложении.
     *
     * @return 200 OK с сообщением об успешном выходе.
     */
    @PostMapping("/logout")
    public ResponseEntity<String> logout() {
        SecurityContextHolder.clearContext(); // Очистка контекста безопасности
        return ResponseEntity.ok("Logout successful");
    }
}
