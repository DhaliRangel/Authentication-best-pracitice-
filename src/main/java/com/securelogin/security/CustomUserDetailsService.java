package com.securelogin.security;

import com.securelogin.entity.User;
import com.securelogin.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return new CustomUserDetails(user);
    }

    private static class CustomUserDetails implements UserDetails {
        private final User user;

        public CustomUserDetails(User user) {
            this.user = user;
        }

        public User getUser() {
            return user;
        }

        @Override
        public String getUsername() {
            return user.getUsername();
        }

        @Override
        public String getPassword() {
            return user.getPasswordHash();
        }

        @Override
        public java.util.Collection<? extends org.springframework.security.core.GrantedAuthority> getAuthorities() {
            return Collections.singletonList(() -> "ROLE_USER");
        }

        @Override
        public boolean isAccountNonExpired() {
            return user.getAccountExpiresAt() == null || 
                   user.getAccountExpiresAt().isAfter(java.time.Instant.now());
        }

        @Override
        public boolean isAccountNonLocked() {
            return !user.isAccountLocked();
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return user.getCredentialsExpiresAt() == null || 
                   user.getCredentialsExpiresAt().isAfter(java.time.Instant.now());
        }

        @Override
        public boolean isEnabled() {
            return user.isAccountEnabled();
        }
    }
}
