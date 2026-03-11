package com.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.Set;

public record UserUpdateDto(
        @NotBlank(message = "The first name is required")
        String firstName,

        @NotBlank(message = "The last name is required")
        String lastName,

        @Email(message = "Email invalid")
        @NotBlank(message = "The email is required")
        String email,

        @NotNull(message = "Status is required")
        Boolean isActive,

        @NotEmpty(message = "The last name cannot be empty.")
        Set<String>roles
) {
}
