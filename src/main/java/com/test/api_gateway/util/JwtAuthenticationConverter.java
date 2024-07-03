package com.test.api_gateway.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationConverter implements ServerAuthenticationConverter {
    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        String token = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);

            // Validate and parse the token
            if (jwtUtil.validateToken(token)) {
                String username = jwtUtil.extractUsername(token);
                List<SimpleGrantedAuthority> authorities = (List<SimpleGrantedAuthority>) jwtUtil.extractAllClaims(token)
                        .get("roles", List.class).stream()
                        .map(role -> new SimpleGrantedAuthority((String) role))
                        .collect(Collectors.toList());

                // Return the authentication object
                Authentication auth = new UsernamePasswordAuthenticationToken(username, token, authorities);
                return Mono.just(auth);
            }
        }
        return Mono.empty();
    }
}
