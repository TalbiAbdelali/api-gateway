package com.test.api_gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtil {
    @Value("${jwt.secret}")
    private String secretString;

    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        // Ensure the secret is at least 256 bits
        if (secretString.length() < 32) {
            throw new IllegalArgumentException("The secret key must be at least 256 bits (32 characters) long.");
        }
        secretKey = Keys.hmacShaKeyFor(secretString.getBytes());
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public boolean validateToken(String token) {
        return !extractAllClaims(token).getExpiration().before(new Date());
    }

    public String generateToken(String username) {
        return createToken(username);
    }

    private String createToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10 hours expiration
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }
}
