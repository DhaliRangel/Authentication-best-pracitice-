package com.securelogin.security;

import com.securelogin.repository.LoginAttemptRepository;
import com.securelogin.repository.UserRepository;
import com.securelogin.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class RateLimitService {

    private final LoginAttemptRepository loginAttemptRepository;
    private final UserRepository userRepository;

    @Value("${app.security.rate-limit.max-attempts:5}")
    private int maxAttempts;

    @Value("${app.security.rate-limit.lockout-duration:15m}")
    private String lockoutDurationStr;

    @Value("${app.security.rate-limit.attempt-window:5m}")
    private String attemptWindowStr;

    public boolean isAccountLocked(String username) {
        return userRepository.findByUsername(username)
            .map(user -> {
                if (!user.isAccountLocked()) {
                    return false;
                }
                Duration lockout = parseDuration(lockoutDurationStr);
                if (user.getLockTime() != null && 
                    user.getLockTime().plus(lockout).isBefore(Instant.now())) {
                    unlockAccount(user);
                    return false;
                }
                return true;
            })
            .orElse(false);
    }

    public void recordFailedAttempt(String username, String ipAddress) {
        userRepository.findByUsername(username).ifPresent(user -> {
            int attempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(attempts);
            user.setLastFailedAttempt(Instant.now());

            if (attempts >= maxAttempts) {
                user.setAccountLocked(true);
                user.setLockTime(Instant.now());
                log.warn("Account locked for user {} due to {} failed attempts from IP {}",
                    username, attempts, ipAddress);
            }

            userRepository.save(user);
        });
    }

    public void recordSuccessfulLogin(String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            user.setFailedAttempts(0);
            user.setLastFailedAttempt(null);
            user.setLastLoginAt(Instant.now());
            userRepository.save(user);
        });
    }

    public void unlockAccount(User user) {
        user.setAccountLocked(false);
        user.setLockTime(null);
        user.setFailedAttempts(0);
        userRepository.save(user);
        log.info("Account unlocked for user {}", user.getUsername());
    }

    public boolean isIpRateLimited(String ipAddress) {
        Duration window = parseDuration(attemptWindowStr);
        Instant since = Instant.now().minus(window);
        long attempts = loginAttemptRepository.countFailedAttemptsByIp(ipAddress, since);
        return attempts >= maxAttempts * 3;
    }

    public boolean isUsernameRateLimited(String username) {
        Duration window = parseDuration(attemptWindowStr);
        Instant since = Instant.now().minus(window);
        long attempts = loginAttemptRepository.countFailedAttemptsByUsername(username, since);
        return attempts >= maxAttempts * 2;
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
