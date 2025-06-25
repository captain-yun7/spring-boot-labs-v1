package com.captainyun7.ch505oauthspringsecuritylogin.security;

import com.captainyun7.ch505oauthspringsecuritylogin.domain.RefreshToken;
import com.captainyun7.ch505oauthspringsecuritylogin.domain.User;
import com.captainyun7.ch505oauthspringsecuritylogin.repository.UserRepository;
import com.captainyun7.ch505oauthspringsecuritylogin.service.RefreshTokenService;
import com.captainyun7.ch505oauthspringsecuritylogin.util.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, 
                                       Authentication authentication) throws IOException, ServletException {
        String email;
        Object principal = authentication.getPrincipal();
        
        if (principal instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) principal;
            email = oidcUser.getEmail();
        } else if (principal instanceof OAuth2User) {
            OAuth2User oAuth2User = (OAuth2User) principal;
            email = (String) oAuth2User.getAttributes().get("email");
        } else {
            getRedirectStrategy().sendRedirect(request, response, "/login?error=unsupported_principal_type");
            return;
        }
        
        if (email == null || email.isEmpty()) {
            getRedirectStrategy().sendRedirect(request, response, "/login?error=email_not_found");
            return;
        }
        
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            getRedirectStrategy().sendRedirect(request, response, "/login?error=user_not_found");
            return;
        }
        
        User user = userOptional.get();
        
        // JWT 토큰 생성
        UserDetails userDetails = org.springframework.security.core.userdetails.User
            .withUsername(user.getUsername())
            .password(user.getPassword() != null ? user.getPassword() : "")
            .authorities(Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole())))
            .build();

        String accessToken = jwtUtil.generateToken(userDetails);
        
        // 리프레시 토큰 생성
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getUsername());
        
        // 리다이렉트 URL
        String targetUrl = UriComponentsBuilder.fromUriString("/oauth2/redirect")
            .queryParam("token", accessToken)
            .queryParam("refreshToken", refreshToken.getToken())
            .build().toUriString();
        
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
} 