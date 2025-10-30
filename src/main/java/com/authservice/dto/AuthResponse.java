package com.authservice.dto;

import java.util.UUID;

public record AuthResponse (
        String token,
        String refreshToken,
        UUID userId
) {}
