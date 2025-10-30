package com.authservice.exception;

public class InvalidTokenException extends RuntimeException {
    // Constructor que recibe un mensaje (usado para explicar el error)
    public InvalidTokenException(String message) {
        super(message);
    }

    // Opcional: Constructor que incluye la causa raíz
    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
