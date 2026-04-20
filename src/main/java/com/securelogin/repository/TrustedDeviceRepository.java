package com.securelogin.repository;

import com.securelogin.entity.TrustedDevice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface TrustedDeviceRepository extends JpaRepository<TrustedDevice, Long> {

    Optional<TrustedDevice> findByUserIdAndDeviceFingerprintAndRevokedFalse(Long userId, String deviceFingerprint);

    List<TrustedDevice> findByUserIdAndRevokedFalse(Long userId);

    @Query("SELECT td FROM TrustedDevice td WHERE td.expiresAt < :now OR td.revoked = true")
    List<TrustedDevice> findExpiredOrRevokedDevices(@Param("now") Instant now);

    @Modifying
    @Query("DELETE FROM TrustedDevice td WHERE td.user.id = :userId")
    void deleteAllByUserId(@Param("userId") Long userId);

    @Modifying
    @Query("UPDATE TrustedDevice td SET td.lastUsedAt = :lastUsedAt WHERE td.id = :deviceId")
    void updateLastUsedAt(@Param("deviceId") Long deviceId, @Param("lastUsedAt") Instant lastUsedAt);
}
