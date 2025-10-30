package com.authservice.service;

import com.authservice.exception.InvalidTokenException;
import com.authservice.model.PasswordResetToken;
import com.authservice.model.User;
import com.authservice.repository.PasswordResetTokenRepository;
import com.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.ZonedDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    // ------------------------------------------
    // 1. FORGOT PASSWORD (Genera y Envía)
    // ------------------------------------------
    public void createPasswordResetToken(String email) {
        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            // Silenciosamente terminar si el usuario no existe (seguridad)
            return;
        }

        // 1. Generar y guardar el token
        String tokenValue = UUID.randomUUID().toString();
        PasswordResetToken token = new PasswordResetToken(user, tokenValue);
        tokenRepository.save(token); // La entidad debe calcular el expiryDate

        // 2. Enviar el correo
        String resetLink = "https://tufrontend.com/reset-password?token=" + tokenValue;
        emailService.sendResetEmail(user.getEmail(), resetLink);
    }

    // ------------------------------------------
    // 2. RESET PASSWORD (Valida y Actualiza)
    // ------------------------------------------
    public boolean resetPassword(String tokenValue, String newPassword) {
        PasswordResetToken token = tokenRepository.findByTokenHash(tokenValue)
                .orElseThrow(() -> new InvalidTokenException("Token no encontrado."));

        // C. Chequeo de Token
        if (token.getExpiryDate().isBefore(ZonedDateTime.now()) || token.isUsed()) {
            throw new InvalidTokenException("Token expirado o ya usado.");
        }

        // D. Actualizar Contraseña
        User user = token.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // E. Invalidar Token
        token.setUsed(true);
        tokenRepository.save(token);

        return true;
    }
}
