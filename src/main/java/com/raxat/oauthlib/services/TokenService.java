    package com.raxat.oauthlib.services;

    import io.jsonwebtoken.security.Keys;
    import org.springframework.beans.factory.annotation.Value;
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
        @Value("${jwt.secret}")
        private String secret;

        @Value("${jwt.expirationMs}")
        private long expirationMs;  // Changed from int to long

        public String generateToken(String username) {
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", username);
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

        public boolean validateToken(String token, String username) {
            final String extractedUsername = extractUsername(token);
            return (extractedUsername != null && extractedUsername.equals(username) && !isTokenExpired(token));
        }

    }
