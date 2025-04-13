package com.raxat.oauthlib.controllers;

import com.raxat.oauthlib.dto.AuthRequest;
import com.raxat.oauthlib.models.JwtToken;
import com.raxat.oauthlib.models.User;
import com.raxat.oauthlib.services.TokenService;
import com.raxat.oauthlib.services.UserService;
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

    @PostMapping("/login")
    public ResponseEntity<JwtToken> login(@RequestBody AuthRequest requestedUser) {
        User user = userService.getUserByUsername(requestedUser.username());

        if (user == null || !passwordEncoder.matches(requestedUser.password(), user.getPassword())) {
            return ResponseEntity.badRequest().body(null);
        }

        JwtToken token = jwtService.generateToken(user);
        return ResponseEntity.ok(token);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtToken> refreshToken(@RequestBody JwtToken token, @RequestBody String username) {
        JwtToken newToken = jwtService.refreshToken(token);
        return ResponseEntity.ok(newToken);
    }
}
