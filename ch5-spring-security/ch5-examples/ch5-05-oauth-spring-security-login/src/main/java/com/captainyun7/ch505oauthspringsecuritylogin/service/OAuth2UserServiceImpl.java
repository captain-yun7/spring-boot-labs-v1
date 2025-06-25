package com.captainyun7.ch505oauthspringsecuritylogin.service;

import com.captainyun7.ch505oauthspringsecuritylogin.domain.User;
import com.captainyun7.ch505oauthspringsecuritylogin.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2UserServiceImpl extends OidcUserService {

    private final UserRepository userRepository;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        // 기본 OIDC 사용자 로드
        OidcUser oidcUser = super.loadUser(userRequest);
        
        try {
            // 사용자 정보 처리
            User user = processUserInfo(oidcUser.getAttributes());
            
            // OIDC 사용자 반환
            return new DefaultOidcUser(
                Collections.singleton(new SimpleGrantedAuthority("ROLE_" + user.getRole())),
                oidcUser.getIdToken(),
                oidcUser.getUserInfo(),
                "sub"  // Google OIDC uses "sub" as the name attribute key
            );
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException("인증 처리 중 오류 발생", ex);
        }
    }
    
    private User processUserInfo(Map<String, Object> attributes) {
        GoogleOAuth2UserInfo userInfo = new GoogleOAuth2UserInfo(attributes);
        
        if (!StringUtils.hasText(userInfo.getEmail())) {
            throw new OAuth2AuthenticationException("이메일을 찾을 수 없습니다");
        }

        Optional<User> userOptional = userRepository.findByEmail(userInfo.getEmail());
        
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (!user.getProvider().equals("google")) {
                throw new OAuth2AuthenticationException("이미 다른 공급자로 가입한 이메일입니다: " + user.getProvider());
            }
            return updateExistingUser(user, userInfo);
        } else {
            return registerNewUser(userInfo);
        }
    }

    private User registerNewUser(GoogleOAuth2UserInfo userInfo) {
        User user = User.builder()
                .provider("google")
                .providerId(userInfo.getId())
                .name(userInfo.getName())
                .email(userInfo.getEmail())
                .username(userInfo.getEmail())
                .imageUrl(userInfo.getImageUrl())
                .role("USER")
                .build();
        
        return userRepository.save(user);
    }

    private User updateExistingUser(User existingUser, GoogleOAuth2UserInfo userInfo) {
        existingUser.setName(userInfo.getName());
        existingUser.setImageUrl(userInfo.getImageUrl());
        return userRepository.save(existingUser);
    }

    // Google OIDC 사용자 정보를 매핑하는 내부 클래스
    private static class GoogleOAuth2UserInfo {
        private final Map<String, Object> attributes;

        public GoogleOAuth2UserInfo(Map<String, Object> attributes) {
            this.attributes = attributes;
        }

        public String getId() {
            return (String) attributes.get("sub");
        }

        public String getName() {
            return (String) attributes.getOrDefault("name", "");
        }

        public String getEmail() {
            return (String) attributes.getOrDefault("email", "");
        }

        public String getImageUrl() {
            return (String) attributes.getOrDefault("picture", "");
        }
    }
}