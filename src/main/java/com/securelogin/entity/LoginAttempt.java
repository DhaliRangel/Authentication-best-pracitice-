package com.securelogin.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

@Entity
@Table(name = "login_attempts")
@Data
public class LoginAttempt {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(nullable = false)
    private String username;

    private String email;

    @Column(nullable = false)
    private String ipAddress;

    private String userAgent;

    private String userAgentParsed;

    private String deviceFingerprint;

    private String country;

    private String city;

    @Column(nullable = false)
    private boolean successful;

    private String failureReason;

    @Column(nullable = false)
    private Instant attemptedAt;

    private Double latitude;

    private Double longitude;

    @PrePersist
    protected void onCreate() {
        attemptedAt = Instant.now();
    }
}
