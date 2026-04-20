package com.securelogin.repository;

import com.securelogin.entity.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    @Query("SELECT COUNT(la) FROM LoginAttempt la WHERE la.ipAddress = :ip AND la.attemptedAt > :since AND la.successful = false")
    long countFailedAttemptsByIp(@Param("ip") String ip, @Param("since") Instant since);

    @Query("SELECT COUNT(la) FROM LoginAttempt la WHERE la.username = :username AND la.attemptedAt > :since AND la.successful = false")
    long countFailedAttemptsByUsername(@Param("username") String username, @Param("since") Instant since);

    @Query("SELECT la FROM LoginAttempt la WHERE la.username = :username ORDER BY la.attemptedAt DESC")
    List<LoginAttempt> findByUsernameOrderByAttemptedAtDesc(@Param("username") String username);

    @Query("SELECT la FROM LoginAttempt la WHERE la.ipAddress = :ip ORDER BY la.attemptedAt DESC")
    List<LoginAttempt> findByIpOrderByAttemptedAtDesc(@Param("ip") String ip);

    @Query("SELECT la FROM LoginAttempt la WHERE la.successful = true ORDER BY la.attemptedAt DESC")
    List<LoginAttempt> findRecentSuccessfulLogins();

    @Modifying
    @Query("DELETE FROM LoginAttempt la WHERE la.attemptedAt < :before")
    void deleteOldAttempts(@Param("before") Instant before);
}
