package com.authservice.dto;

import java.util.UUID;

public record UserListDto (
        UUID id,
        String email,
        String firstName,
        String lastName
) {
}
