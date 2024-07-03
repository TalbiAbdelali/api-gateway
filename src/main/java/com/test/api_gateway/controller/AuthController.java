package com.test.api_gateway.controller;

import com.test.api_gateway.model.AuthRequest;
import com.test.api_gateway.model.AuthResponse;
import com.test.api_gateway.service.CustomUserDetailsService;
import com.test.api_gateway.util.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;

    public AuthController(JwtUtil jwtUtil, CustomUserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(@RequestBody AuthRequest authRequest) {
        return userDetailsService.findByUsername(authRequest.getUsername())
                .switchIfEmpty(Mono.error(new UsernameNotFoundException("User not found")))
                .map(userDetails -> {
                    if (authRequest.getPassword().equals(userDetails.getPassword())) {
                        String token = jwtUtil.generateToken(userDetails.getUsername());
                        return ResponseEntity.ok(new AuthResponse(token));
                    } else {
                        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
                    }
                });
    }
}
