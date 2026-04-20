package com.securelogin.service;

import com.securelogin.dto.*;
import com.securelogin.entity.User;
import com.securelogin.entity.LoginAttempt;
import com.securelogin.entity.TrustedDevice;
import com.securelogin.exception.*;
import com.securelogin.repository.UserRepository;
import com.securelogin.repository.TrustedDeviceRepository;
import com.securelogin.security.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final TrustedDeviceRepository trustedDeviceRepository;
    private final PasswordHashingService passwordHashingService;
    private final RateLimitService rateLimitService;
    private final SecurityMonitoringService monitoringService;
    private final MfaService mfaService;
    private final EmailService emailService;

    @Value("${app.security.session.idle-timeout:30m}")
    private String idleTimeout;

    @Value("${app.security.session.absolute-timeout:120m}")
    private String absoluteTimeout;

    @Transactional
    public User register(RegisterRequest request, HttpServletRequest httpRequest) {
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new ValidationException("Passwords do not match");
        }

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new ValidationException("Username already exists");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ValidationException("Email already exists");
        }

        String salt = passwordHashingService.generateSalt();
        String passwordHash = passwordHashingService.hashPassword(request.getPassword(), salt);

        User user = User.builder()
            .username(request.getUsername())
            .email(request.getEmail())
            .passwordHash(passwordHash)
            .salt(salt)
            .passwordAlgorithm("argon2")
            .mfaEnabled(false)
            .accountLocked(false)
            .accountEnabled(true)
            .build();

        user = userRepository.save(user);

        log.info("New user registered: {}", user.getUsername());
        monitoringService.logLoginAttempt(
            user.getUsername(),
            user.getEmail(),
            getClientIp(httpRequest),
            httpRequest.getHeader("User-Agent"),
            true,
            null
        );

        return user;
    }

    @Transactional
    public LoginResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        String clientIp = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        if (rateLimitService.isAccountLocked(request.getUsername())) {
            monitoringService.logLoginAttempt(request.getUsername(), null, clientIp, userAgent, false, "ACCOUNT_LOCKED");
            throw new AccountLockedException("Account is temporarily locked due to too many failed attempts");
        }

        if (rateLimitService.isIpRateLimited(clientIp)) {
            throw new RateLimitException("Too many failed attempts. Please try again later.");
        }

        User user = userRepository.findByUsername(request.getUsername())
            .orElseThrow(() -> {
                monitoringService.logLoginAttempt(request.getUsername(), null, clientIp, userAgent, false, "USER_NOT_FOUND");
                return new InvalidCredentialsException("Invalid username or password");
            });

        if (!passwordHashingService.verifyPassword(request.getPassword(), user.getSalt(), user.getPasswordHash())) {
            rateLimitService.recordFailedAttempt(request.getUsername(), clientIp);
            monitoringService.logLoginAttempt(user.getUsername(), user.getEmail(), clientIp, userAgent, false, "INVALID_PASSWORD");
            throw new InvalidCredentialsException("Invalid username or password");
        }

        if (user.isMfaEnabled()) {
            if (request.getTotpCode() == null || request.getTotpCode().isEmpty()) {
                return LoginResponse.builder()
                    .mfaRequired(true)
                    .message("MFA verification required")
                    .username(user.getUsername())
                    .build();
            }

            if (!mfaService.verifyCode(user.getMfaSecret(), request.getTotpCode())) {
                monitoringService.logLoginAttempt(user.getUsername(), user.getEmail(), clientIp, userAgent, false, "INVALID_MFA");
                throw new InvalidCredentialsException("Invalid MFA code");
            }
        }

        rateLimitService.recordSuccessfulLogin(user.getUsername());
        monitoringService.logLoginAttempt(user.getUsername(), user.getEmail(), clientIp, userAgent, true, null);

        HttpSession session = httpRequest.getSession(true);
        session.setAttribute("userId", user.getId());
        session.setAttribute("username", user.getUsername());
        session.setMaxInactiveInterval((int) parseDuration(idleTimeout).toSeconds());

        if (request.isTrustedDevice() && request.getDeviceFingerprint() != null) {
            saveTrustedDevice(user, request.getDeviceFingerprint(), clientIp, userAgent);
        }

        checkNewDeviceLogin(user, clientIp, userAgent);

        return LoginResponse.builder()
            .success(true)
            .message("Login successful")
            .mfaRequired(false)
            .username(user.getUsername())
            .build();
    }

    private void saveTrustedDevice(User user, String fingerprint, String ip, String userAgent) {
        TrustedDevice device = TrustedDevice.builder()
            .user(user)
            .deviceFingerprint(fingerprint)
            .ipAddress(ip)
            .expiresAt(Instant.now().plus(Duration.ofDays(30)))
            .build();

        trustedDeviceRepository.save(device);
    }

    private void checkNewDeviceLogin(User user, String ip, String userAgent) {
        if (user.getLastLoginIp() != null && !user.getLastLoginIp().equals(ip)) {
            emailService.sendNewLoginNotification(user.getEmail(), ip, userAgent);
            log.info("New device login detected for user {} from IP {}", user.getUsername(), ip);
        }
    }

    @Transactional
    public void logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }

    public boolean isTrustedDevice(String username, String fingerprint) {
        return userRepository.findByUsername(username)
            .map(user -> trustedDeviceRepository
                .findByUserIdAndDeviceFingerprintAndRevokedFalse(user.getId(), fingerprint)
                .isPresent())
            .orElse(false);
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
        return Duration.ofMinutes(30);
    }
}
