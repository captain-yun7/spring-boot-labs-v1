package com.captainyun7.ch505oauthspringsecuritylogin.controller;

import com.captainyun7.ch505oauthspringsecuritylogin.dto.*;
import com.captainyun7.ch505oauthspringsecuritylogin.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    
    private final AuthService authService;
    
    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody SignUpRequest signUpRequest) {
        UserResponse userResponse = authService.register(signUpRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(userResponse);
    }
    
    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        JwtResponse jwtResponse = authService.login(loginRequest);
        return ResponseEntity.ok(jwtResponse);
    }
    
    @PostMapping("/refreshtoken")
    public ResponseEntity<TokenRefreshResponse> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        String newAccessToken = authService.refreshAccessToken(request.getRefreshToken());
        return ResponseEntity.ok(new TokenRefreshResponse(newAccessToken, request.getRefreshToken()));
    }
    
    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        authService.logout();
        return ResponseEntity.ok().build();
    }
    
    /**
     * OAuth2 로그인 관련 정보를 제공하는 엔드포인트
     */
    @GetMapping("/oauth2-providers")
    public ResponseEntity<Map<String, String>> getOAuth2Providers() {
        Map<String, String> providers = new HashMap<>();
        providers.put("google", "/oauth2/authorize/google");
        return ResponseEntity.ok(providers);
    }
} 