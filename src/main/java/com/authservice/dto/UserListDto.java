package com.authservice.dto;

import com.authservice.model.Role;

import java.util.Set;
import java.util.UUID;

public record UserListDto (
        UUID id,
        String email,
        String firstName,
        String lastName,
        Boolean isActive,
        Set<String> roles
) {
}
