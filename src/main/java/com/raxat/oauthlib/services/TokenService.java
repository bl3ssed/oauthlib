    package com.raxat.oauthlib.services;

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
        private long expirationMs;  // Changed from int to long

        public String generateToken(User user) {
            Map<String, Object> claims = new HashMap<>();
            claims.put("username", user.getUsername());
            claims.put("email", user.getEmail());
            claims.put("iat", new Date().getTime());
            return createToken(claims);
        }

        private SecretKey getSigningKey() {
            return Keys.hmacShaKeyFor(secret.getBytes());
        }

        private String createToken(Map<String, Object> claims) {
            return Jwts.builder()
                    .setClaims(claims)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + expirationMs))  // Use expirationMs instead of EXPIRATION_TIME
                    .signWith(getSigningKey())
                    .compact();
        }

        public String extractUsername(String token) {
            return extractClaim(token, Claims::getSubject);
        }

        private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
            final Claims claims = extractAllClaims(token);
            return claimsResolver.apply(claims);
        }

        private Claims extractAllClaims(String token) {
            return Jwts.parserBuilder()  // Вместо устаревшего parser()
                    .setSigningKey(getSigningKey())  // Используем SecretKey вместо String
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        }

        public boolean isTokenExpired(String token) {
            return extractExpiration(token).before(new Date());
        }

        private Date extractExpiration(String token) {
            return extractClaim(token, Claims::getExpiration);
        }

        // Убираем параметр username
        public boolean validateToken(String token) {
            final String username = extractUsername(token);
            return (username != null && !isTokenExpired(token));
        }

        public String refreshToken(String token) {
            String username = null;

            try {
                if (isTokenExpired(token)) {
                    // Токен ещё валиден, но уже считается просроченным — достаём обычным способом
                    username = extractUsername(token);
                } else {
                    return token; // если не истёк — возвращаем его как есть
                }
            } catch (ExpiredJwtException e) {
                Claims claims = e.getClaims();
                username = (String) claims.get("username"); // или getSubject(), если ты используешь subject
                if (username != null) {
                    User user = userService.getUserByUsername(username);
                    if (user != null) {
                        return generateToken(user);
                    }
                }
            }

            // Попытка обновить токен

            return token;

        }
    }
