package com.authservice.service;

import com.authservice.repository.RefreshTokenRepository;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Instant;

public class RefreshTokenCleanupService {
    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenCleanupService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Scheduled(cron = "0 0 * * * *") // cada hora
    public void removeExpiredTokens() {
        Instant now = Instant.now();
        refreshTokenRepository.deleteAllByExpiresAtBeforeOrRevokedAtIsNotNull(now);
        System.out.println("🧹 Expired and revoked refresh tokens cleaned up");
    }
}
