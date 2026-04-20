package com.securelogin.security;

import com.securelogin.entity.LoginAttempt;
import com.securelogin.entity.TrustedDevice;
import com.securelogin.entity.User;
import com.securelogin.repository.LoginAttemptRepository;
import com.securelogin.repository.TrustedDeviceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityMonitoringService {

    private final LoginAttemptRepository loginAttemptRepository;
    private final TrustedDeviceRepository trustedDeviceRepository;

    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        .withZone(ZoneId.systemDefault());

    @Transactional
    public void logLoginAttempt(String username, String email, String ipAddress, String userAgent,
                                boolean successful, String failureReason) {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUsername(username);
        attempt.setEmail(email);
        attempt.setIpAddress(ipAddress);
        attempt.setUserAgent(userAgent);
        attempt.setSuccessful(successful);
        attempt.setFailureReason(failureReason);
        attempt.setAttemptedAt(Instant.now());

        loginAttemptRepository.save(attempt);

        if (successful) {
            log.info("Successful login - User: {}, IP: {}, Time: {}",
                username, ipAddress, DATE_FORMAT.format(Instant.now()));
        } else {
            log.warn("Failed login attempt - User: {}, IP: {}, Reason: {}, Time: {}",
                username, ipAddress, failureReason, DATE_FORMAT.format(Instant.now()));
            checkForSuspiciousActivity(username, ipAddress);
        }
    }

    private void checkForSuspiciousActivity(String username, String ipAddress) {
        Instant oneHourAgo = Instant.now().minusSeconds(3600);
        long recentFailures = loginAttemptRepository.countFailedAttemptsByIp(ipAddress, oneHourAgo);

        if (recentFailures > 10) {
            log.error("SUSPICIOUS: Multiple failed attempts from IP {} - {} attempts in the last hour",
                ipAddress, recentFailures);
            alertSecurityTeam("BRUTE_FORCE_ATTEMPT", 
                Map.of("ip", ipAddress, "username", username, "attempts", recentFailures));
        }
    }

    private void alertSecurityTeam(String alertType, Map<String, Object> details) {
        log.error("SECURITY ALERT - Type: {}, Details: {}", alertType, details);
    }

    @Scheduled(fixedRate = 3600000)
    @Transactional
    public void cleanupOldAttempts() {
        Instant cutoff = Instant.now().minusSeconds(7776000);
        loginAttemptRepository.deleteOldAttempts(cutoff);
        loginAttemptRepository.deleteOldAttempts(cutoff);
        log.info("Cleaned up login attempts older than 90 days");
    }

    @Scheduled(fixedRate = 3600000)
    @Transactional
    public void cleanupExpiredDevices() {
        Instant now = Instant.now();
        List<TrustedDevice> expiredDevices = trustedDeviceRepository.findExpiredOrRevokedDevices(now);
        
        for (TrustedDevice device : expiredDevices) {
            log.info("Cleaning up expired device: {} for user {}",
                device.getDeviceFingerprint(), device.getUser().getUsername());
        }
    }

    public Map<String, Object> getSecurityStats() {
        Map<String, Object> stats = new HashMap<>();
        
        Instant oneDayAgo = Instant.now().minusSeconds(86400);
        Instant oneWeekAgo = Instant.now().minusSeconds(604800);

        stats.put("successfulLogins24h", loginAttemptRepository.findRecentSuccessfulLogins().stream()
            .filter(a -> a.getAttemptedAt().isAfter(oneDayAgo)).count());
        
        stats.put("failedLogins24h", loginAttemptRepository.countFailedAttemptsByIp("%", oneDayAgo));
        
        stats.put("activeDevices", trustedDeviceRepository.count());

        return stats;
    }

    public List<LoginAttempt> getRecentFailedAttemptsForUser(String username) {
        return loginAttemptRepository.findByUsernameOrderByAttemptedAtDesc(username);
    }

    public List<LoginAttempt> getRecentAttemptsFromIp(String ipAddress) {
        return loginAttemptRepository.findByIpOrderByAttemptedAtDesc(ipAddress);
    }
}
