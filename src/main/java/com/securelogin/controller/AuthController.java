package com.securelogin.controller;

import com.securelogin.dto.*;
import com.securelogin.entity.User;
import com.securelogin.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserDto>> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {
        User user = authService.register(request, httpRequest);
        return ResponseEntity.ok(ApiResponse.success("Registration successful", toUserDto(user)));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        LoginResponse response = authService.login(request, httpRequest);
        return ResponseEntity.ok(ApiResponse.success("Login successful", response));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(HttpServletRequest request) {
        authService.logout(request);
        return ResponseEntity.ok(ApiResponse.success("Logged out successfully"));
    }

    @GetMapping("/csrf-token")
    public ResponseEntity<ApiResponse<CsrfTokenDto>> getCsrfToken(
            @RequestAttribute(name = "_csrf", required = false) org.springframework.security.web.csrf.CsrfToken csrfToken) {
        if (csrfToken == null) {
            return ResponseEntity.ok(ApiResponse.success("CSRF token not available", null));
        }
        return ResponseEntity.ok(ApiResponse.success("CSRF token retrieved", 
            new CsrfTokenDto(csrfToken.getToken(), csrfToken.getHeaderName())));
    }

    private UserDto toUserDto(User user) {
        return UserDto.builder()
            .id(user.getId())
            .username(user.getUsername())
            .email(user.getEmail())
            .mfaEnabled(user.isMfaEnabled())
            .build();
    }

    @lombok.Data
    @lombok.AllArgsConstructor
    private static class CsrfTokenDto {
        private String token;
        private String headerName;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.AllArgsConstructor
    @lombok.NoArgsConstructor
    private static class UserDto {
        private Long id;
        private String username;
        private String email;
        private boolean mfaEnabled;
    }
}
