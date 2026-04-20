package com.securelogin.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "trusted_devices")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TrustedDevice {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String deviceFingerprint;

    private String deviceName;

    private String deviceType;

    private String browser;

    private String operatingSystem;

    private String ipAddress;

    private String location;

    @Column(nullable = false)
    private Instant createdAt;

    private Instant lastUsedAt;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private boolean revoked;

    private Instant revokedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
        lastUsedAt = Instant.now();
        revoked = false;
    }
}
