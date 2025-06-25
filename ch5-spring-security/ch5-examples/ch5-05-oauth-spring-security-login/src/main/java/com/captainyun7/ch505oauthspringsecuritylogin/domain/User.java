package com.captainyun7.ch505oauthspringsecuritylogin.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    private String password;
    private String email;
    private String role; // "USER", "ADMIN"
    
    // OAuth2 관련 필드
    private String provider; // "github", "google" 등
    private String providerId; // OAuth2 공급자에서 제공하는 고유 ID
    private String name; // 사용자 실명
    private String imageUrl; // 프로필 이미지 URL
} 