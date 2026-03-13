package com.authservice.service;

import com.authservice.model.RefreshToken;
import com.authservice.model.User;
import com.authservice.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;

//    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
//        this.refreshTokenRepository = refreshTokenRepository;
//    }

    public RefreshToken createToken(User user, String rawToken, Instant expiresAt, String ipAddress) {
        RefreshToken token = new RefreshToken();
        token.setUser(user);
        token.setTokenHash(hashToken(rawToken)); // 👈 almacenar hash
        token.setExpiresAt(expiresAt);
        token.setIpAddress(ipAddress);
        return refreshTokenRepository.save(token);
    }

    public Optional<RefreshToken> validateToken(String rawToken) {
        String hash = hashToken(rawToken);
        return refreshTokenRepository.findByTokenHash(hash)
                .filter(t -> !t.isExpired() && !t.isRevoked());
    }

//    public void revokeRefreshToken(String rawToken) {
//        String hashed = hashToken(rawToken); // misma función que usaste al guardar
//        RefreshToken token = refreshTokenRepository.findByTokenHash(hashed)
//                .orElseThrow(() -> new RuntimeException("Refresh token not found"));
//
//        token.setRevokedAt(Instant.now());
//        refreshTokenRepository.save(token);
//    }

    public void revokeToken(String fullRefreshToken) {
        if (fullRefreshToken == null || !fullRefreshToken.contains(".")) {
            throw new RuntimeException("Invalid refresh token format.");
        }

        String[] parts = fullRefreshToken.split("\\.");
        UUID tokenId = UUID.fromString(parts[0]);
        String rawSecret = parts[1];

        // 2. Buscar directamente por ID (mucho más rápido)
        RefreshToken token = refreshTokenRepository.findById(tokenId)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        // 3. Validar el secreto
        if (!passwordEncoder.matches(rawSecret, token.getTokenHash())) {
            throw new RuntimeException("Invalid refresh token secret");
        }

        // 4. Revocar si no estaba ya revocado
        if (token.getRevokedAt() == null) {
            token.setRevokedAt(Instant.now());
            refreshTokenRepository.save(token);
        }
    }

    private String hashToken(String token) {
        // Puedes usar SHA-256 o BCrypt, no guardes el token plano
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedHash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encodedHash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


}
