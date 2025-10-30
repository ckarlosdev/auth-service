package com.authservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    // Asume que esta variable está definida en application.properties
    // Ej: spring.mail.username=noreply@tudominio.com
    private static final String NOREPLY_ADDRESS = "per.ckarlos@gmail.com";

    /**
     * Envía el correo electrónico de restablecimiento de contraseña.
     * @param toEmail La dirección de correo del destinatario.
     * @param resetLink El enlace único de restablecimiento de contraseña.
     */
    public void sendResetEmail(String toEmail, String resetLink) {

        SimpleMailMessage message = new SimpleMailMessage();

        // 1. Configuración del remitente y destinatario
        message.setFrom(NOREPLY_ADDRESS);
        message.setTo(toEmail);

        // 2. Asunto del correo
        message.setSubject("Solicitud de Restablecimiento de Contraseña");

        // 3. Contenido del correo (puede ser más elaborado con HTML)
        String content = "Hola,\n\n"
                + "Recibimos una solicitud para restablecer tu contraseña. "
                + "Haz clic en el siguiente enlace para continuar:\n\n"
                + resetLink + "\n\n"
                + "Si no solicitaste este cambio, puedes ignorar este correo. "
                + "Este enlace expirará en 60 minutos.";

        message.setText(content);

        // 4. Envío del mensaje
        try {
            mailSender.send(message);
            System.out.println("Correo de restablecimiento enviado con éxito a: " + toEmail);
        } catch (Exception e) {
            System.err.println("Error al enviar el correo a " + toEmail + ": " + e.getMessage());
            // En un entorno de producción, puedes loggear el error con un logger profesional
            // y quizás relanzar una excepción de negocio.
        }
    }
}
