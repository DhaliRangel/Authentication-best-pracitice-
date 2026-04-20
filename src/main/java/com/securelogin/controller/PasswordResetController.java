package com.securelogin.controller;

import com.securelogin.dto.*;
import com.securelogin.entity.PasswordResetToken;
import com.securelogin.entity.User;
import com.securelogin.exception.ResourceNotFoundException;
import com.securelogin.exception.ValidationException;
import com.securelogin.repository.PasswordResetTokenRepository;
import com.securelogin.repository.UserRepository;
import com.securelogin.security.PasswordHashingService;
import com.securelogin.service.EmailService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.time.Instant;

@RestController
@RequestMapping("/api/auth/password-reset")
@RequiredArgsConstructor
public class PasswordResetController {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordHashingService passwordHashingService;
    private final EmailService emailService;

    @Value("${app.security.password-reset.token-expiration:15m}")
    private String tokenExpiration;

    @PostMapping("/request")
    @Transactional
    public ResponseEntity<ApiResponse<Void>> requestPasswordReset(
            @Valid @RequestBody PasswordResetRequest request,
            HttpServletRequest httpRequest) {
        
        String email = request.getEmail();
        userRepository.findByEmail(email).ifPresent(user -> {
            passwordResetTokenRepository.deleteAllTokensForUser(user.getId());
            
            String token = passwordHashingService.generateSecureToken(32);
            String tokenHash = passwordHashingService.hashPassword(token, passwordHashingService.generateSalt());
            
            PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(token)
                .tokenHash(tokenHash)
                .user(user)
                .expiresAt(Instant.now().plus(parseDuration(tokenExpiration)))
                .ipAddress(getClientIp(httpRequest))
                .userAgent(httpRequest.getHeader("User-Agent"))
                .build();
            
            passwordResetTokenRepository.save(resetToken);
            emailService.sendPasswordResetEmail(email, token);
        });

        return ResponseEntity.ok(ApiResponse.success("If an account exists with this email, a password reset link will be sent"));
    }

    @PostMapping("/confirm")
    @Transactional
    public ResponseEntity<ApiResponse<Void>> confirmPasswordReset(
            @Valid @RequestBody PasswordResetConfirmRequest request) {
        
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new ValidationException("Passwords do not match");
        }

        User user = null;
        for (PasswordResetToken token : passwordResetTokenRepository.findAll()) {
            if (!token.isUsed() && 
                token.getExpiresAt().isAfter(Instant.now()) &&
                passwordHashingService.verifyPassword(request.getToken(), token.getSalt(), token.getTokenHash())) {
                user = token.getUser();
                token.setUsed(true);
                token.setUsedAt(Instant.now());
                passwordResetTokenRepository.save(token);
                break;
            }
        }

        if (user == null) {
            throw new ResourceNotFoundException("Invalid or expired token");
        }

        String newSalt = passwordHashingService.generateSalt();
        String newPasswordHash = passwordHashingService.hashPassword(request.getNewPassword(), newSalt);

        user.setSalt(newSalt);
        user.setPasswordHash(newPasswordHash);
        userRepository.save(user);

        passwordResetTokenRepository.deleteAllTokensForUser(user.getId());

        return ResponseEntity.ok(ApiResponse.success("Password reset successfully"));
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private Duration parseDuration(String duration) {
        if (duration.endsWith("m")) {
            return Duration.ofMinutes(Long.parseLong(duration.replace("m", "")));
        } else if (duration.endsWith("h")) {
            return Duration.ofHours(Long.parseLong(duration.replace("h", "")));
        } else if (duration.endsWith("s")) {
            return Duration.ofSeconds(Long.parseLong(duration.replace("s", "")));
        }
        return Duration.ofMinutes(15);
    }
}
