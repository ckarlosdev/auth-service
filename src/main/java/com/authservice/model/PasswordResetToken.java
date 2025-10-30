package com.authservice.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.ZonedDateTime;
import java.util.UUID;

@Entity
@Table(name = "password_reset_token")
@Data
@NoArgsConstructor
public class PasswordResetToken {
    private static final int EXPIRATION_MINUTES = 60; // El token expira en 60 minutos

    @Id
    @Column(columnDefinition = "BINARY(16)")
    private UUID id;

    @PrePersist
    public void ensureId() {
        if (id == null) {
            this.id = UUID.randomUUID();
        }
    }

    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    @OneToOne(targetEntity = User.class, fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "user_id")
    private User user;

    @Column(name = "expiry_date", nullable = false)
    private ZonedDateTime expiryDate;

    @Column(name = "is_used", nullable = false)
    private boolean isUsed = false;

    // Constructor usado por el servicio
    public PasswordResetToken(User user, String token) {
        this.user = user;
        this.tokenHash = token;
        // La fecha de expiración se calcula al momento de la creación
        this.expiryDate = ZonedDateTime.now().plusMinutes(EXPIRATION_MINUTES);
    }
}
