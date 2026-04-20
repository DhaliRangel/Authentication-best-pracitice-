package com.securelogin.repository;

import com.securelogin.entity.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    Optional<PasswordResetToken> findByTokenAndUsedFalseAndExpiresAtAfter(String token, Instant now);

    @Modifying
    @Query("UPDATE PasswordResetToken t SET t.used = true, t.usedAt = :usedAt WHERE t.user.id = :userId AND t.used = false")
    void markAllTokensAsUsedForUser(@Param("userId") Long userId, @Param("usedAt") Instant usedAt);

    @Modifying
    @Query("DELETE FROM PasswordResetToken t WHERE t.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") Instant now);

    @Modifying
    @Query("DELETE FROM PasswordResetToken t WHERE t.user.id = :userId")
    void deleteAllTokensForUser(@Param("userId") Long userId);
}
