package com.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

public record LoginRequest (
        @NotEmpty(message = "The email is required.")
        @Email(message = "Incorrect format email.")
        String email,

        @NotEmpty(message = "The password is required.")
        String password
) {}
