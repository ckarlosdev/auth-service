package com.authservice.dto;

public record PasswordResetRequest(
        String token,
        String newPassword
) {}
