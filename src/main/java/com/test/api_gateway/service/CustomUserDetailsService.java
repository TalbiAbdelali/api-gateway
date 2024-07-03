package com.test.api_gateway.service;

import com.test.api_gateway.model.AuthenticatedUser;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class CustomUserDetailsService implements ReactiveUserDetailsService {
    private final Map<String, UserDetails> users = new ConcurrentHashMap<>();

    public CustomUserDetailsService() {
        // Preload some users
        users.put("user", org.springframework.security.core.userdetails.User
                .withUsername("user")
                .password("password")
                .roles("USER")
                .build());
    }

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        UserDetails user = users.get(username);
        if (user == null) {
            return Mono.error(new UsernameNotFoundException("User not found"));
        }
        return Mono.just(user);
    }
}
