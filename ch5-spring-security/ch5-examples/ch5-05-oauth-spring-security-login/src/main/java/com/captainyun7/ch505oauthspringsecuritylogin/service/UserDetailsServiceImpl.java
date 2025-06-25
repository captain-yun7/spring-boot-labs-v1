package com.captainyun7.ch505oauthspringsecuritylogin.service;

import com.captainyun7.ch505oauthspringsecuritylogin.domain.User;
import com.captainyun7.ch505oauthspringsecuritylogin.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username));

        // OIDC/OAuth2로 가입한 사용자는 데이터베이스에 비밀번호가 null로 저장됩니다.
        // org.springframework.security.core.userdetails.User 객체는 null 비밀번호를 허용하지 않으므로,
        // null일 경우 빈 문자열("")을 비밀번호로 설정하여 UserDetails 객체를 생성합니다.
        // 이 비밀번호는 JWT 토큰 인증 과정에서는 사용되지 않으므로 안전합니다.
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword() != null ? user.getPassword() : "")
                .authorities(Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole())))
                .build();
    }
} 