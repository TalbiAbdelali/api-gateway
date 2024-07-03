package com.test.api_gateway.service;

import com.test.api_gateway.model.AuthenticatedUser;
import com.test.api_gateway.util.JwtUtil;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
@Component
public class AuthenticationManager implements ReactiveAuthenticationManager {
    private final CustomUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    public AuthenticationManager(CustomUserDetailsService userDetailsService, JwtUtil jwtUtil) {
        this.userDetailsService = userDetailsService;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String authToken = authentication.getCredentials().toString();
        String username = jwtUtil.extractUsername(authToken);

        if (username != null && jwtUtil.validateToken(authToken)) {
            Mono<UserDetails> userDetails = userDetailsService.findByUsername(username);
            return userDetails.map(user -> {
                if (user != null) {
                    return new UsernamePasswordAuthenticationToken(
                            new AuthenticatedUser(user.getUsername(), user.getPassword(), user.getAuthorities()),
                            null,
                            user.getAuthorities()
                    );
                } else {
                    throw new UsernameNotFoundException("User not found");
                }
            });
        } else {
            return Mono.empty();
        }
    }
}
