package com.captainyun7.ch505oauthspringsecuritylogin.controller;

import com.captainyun7.ch505oauthspringsecuritylogin.dto.JwtResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "Google OAuth2 로그인 예제 - <a href='/oauth2/authorize/google'>Google로 로그인</a>";
    }

    @GetMapping("/login")
    public String login() {
        return "로그인 페이지 - <a href='/oauth2/authorize/google'>Google로 로그인</a>";
    }
    
    /**
     * OAuth2 로그인 성공 후 리다이렉트되는 페이지
     * 토큰을 JSON 형식으로 반환
     */
    @GetMapping("/oauth2/redirect")
    public ResponseEntity<JwtResponse> oauthRedirect(@RequestParam String token, @RequestParam String refreshToken) {
        return ResponseEntity.ok(new JwtResponse(token, refreshToken));
    }
} 