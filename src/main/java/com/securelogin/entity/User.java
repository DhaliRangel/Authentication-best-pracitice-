package com.securelogin.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "users", indexes = {
    @Index(name = "idx_user_email", columnList = "email"),
    @Index(name = "idx_user_username", columnList = "username")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 50)
    private String username;

    @Column(unique = true, nullable = false, length = 100)
    private String email;

    @Column(nullable = false)
    private String passwordHash;

    @Column(nullable = false)
    private String salt;

    @Column(nullable = false)
    private String passwordAlgorithm;

    @Column(nullable = false)
    private boolean mfaEnabled;

    private String mfaSecret;

    @Column(nullable = false)
    private boolean accountLocked;

    private Instant lockTime;

    private int failedAttempts;

    private Instant lastFailedAttempt;

    @Column(nullable = false)
    private boolean accountEnabled;

    private Instant accountExpiresAt;

    private Instant credentialsExpiresAt;

    private Instant lastLoginAt;

    private String lastLoginIp;

    private String lastLoginDevice;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<PasswordResetToken> passwordResetTokens = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<TrustedDevice> trustedDevices = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<LoginAttempt> loginAttempts = new ArrayList<>();

    @Column(nullable = false)
    private Instant createdAt;

    private Instant updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
        accountEnabled = true;
        passwordAlgorithm = "argon2";
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }
}
