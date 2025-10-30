package com.authservice.controller;

import com.authservice.dto.PasswordResetRequest;
import com.authservice.exception.InvalidTokenException;
import com.authservice.service.PasswordResetService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class PasswordResetController {
    private final PasswordResetService passwordResetService;

    // POST /api/auth/forgot-password
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");

        // Llama al servicio para generar el token y enviar el email.
        // El servicio maneja la lógica de que hacer si el email no existe.
        passwordResetService.createPasswordResetToken(email);

        // Devolvemos un mensaje genérico por seguridad, independientemente de si el email existe o no.
        return ResponseEntity.ok("Si la dirección de correo electrónico está registrada, recibirá un enlace para restablecer su contraseña.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody PasswordResetRequest request) {
        try {
            // Llama al servicio para validar el token y actualizar la contraseña.
            passwordResetService.resetPassword(request.token(), request.newPassword());

            return ResponseEntity.ok("Su contraseña ha sido restablecida con éxito.");

        } catch (InvalidTokenException e) {
            // Maneja el error si el token es inválido o ha expirado.
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            // Maneja otros errores (ej. nueva contraseña débil, error de BD)
            return ResponseEntity.internalServerError().body("Ocurrió un error al intentar restablecer la contraseña.");
        }
    }
}
