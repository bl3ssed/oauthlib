package com.raxat.oauthlib.services;

import com.raxat.oauthlib.models.JwtToken;
import com.raxat.oauthlib.models.User;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Service
public class TokenService {

    @Autowired
    @Lazy
    private UserService userService;
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expirationMs}")
    private long expirationMs;

    @Value("${jwt.expirationMsRefresh}")
    private long expirationMsRefresh;


    public JwtToken generateToken(final User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", user.getUsername());
        claims.put("email", user.getEmail());
        claims.put("iat", new Date().getTime());
        String access = createToken(claims, true);
        String refresh = createToken(claims, false);

        return new JwtToken(access, refresh);
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    private String createToken(Map<String, Object> claims, boolean isAccess) {
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + (isAccess? expirationMs : expirationMsRefresh)))
                .signWith(getSigningKey())
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, claims -> claims.get("username")).toString();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenExpired(String token) {
        try {
            Date expirationDate = extractExpiration(token);
            return expirationDate.before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public boolean validateToken(String token) {
        final String username = extractUsername(token);
        return (username != null && !isTokenExpired(token));
    }

    public JwtToken refreshToken(JwtToken token) {
        String username = null;

        try {
            if (isTokenExpired(token.getToken())) {
                username = extractUsername(this.extractUsername(token.getToken()));
            } else {
                return token;
            }
        } catch (ExpiredJwtException e) {
            Claims claims = e.getClaims();
            username = (String) claims.get("username");
            if (username != null) {
                User user = userService.getUserByUsername(username);
                if (user != null) {
                    return generateToken(user);
                }
            }
        }

        return token;

    }
}
