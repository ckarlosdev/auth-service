package com.authservice.dto;

import java.util.UUID;

public record AdminChangePasswordRequest(
        UUID userId,
        String newPassword) {}
