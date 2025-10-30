package com.authservice.repository;

import com.authservice.model.RefreshToken;
import com.authservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    List<RefreshToken> findAllByUser(User user);

    void deleteAllByExpiresAtBeforeOrRevokedAtIsNotNull(Instant now);

    @Query("SELECT r FROM RefreshToken r WHERE r.revokedAt IS NULL AND r.expiresAt > CURRENT_TIMESTAMP")
    List<RefreshToken> findAllByRevokedAtIsNull();
}
