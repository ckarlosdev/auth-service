package com.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotEmpty(message = "Email cannot be empty.")
        @Email(message = "Invalid format.")
        String email,

        @NotEmpty(message = "The password cannot be empty.")
        @Size(min = 8, message = "The password must be at least 8 character long.")
        String password,

        @NotEmpty(message = "The first name cannot be empty.")
        String firstName,

        @NotEmpty(message = "The last name cannot be empty.")
        String lastName
) {}
