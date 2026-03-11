package com.authservice.controller;

import com.authservice.dto.*;
import com.authservice.model.User;
import com.authservice.repository.RefreshTokenRepository;
import com.authservice.repository.UserRepository;
import com.authservice.service.AuthService;
import com.authservice.service.JwtService;
import com.authservice.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    // -------------------------------
    // LOGIN / REGISTER RECORDS
    // -------------------------------
    record LoginRequest(String email, String password){}
    record RegisterRequest(String email, String password, String firstName, String lastName, Set<String> roles) {}
    record RefreshRequest(String refreshToken){}
    record RevokeRequest(String refreshToken){}

    // -------------------------------
    // REGISTER
    // -------------------------------
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
        try {
            Set<String> roles = (request.roles() == null || request.roles().isEmpty())
                    ? Set.of("ROLE_USER")
                    : request.roles();

            User newUser = authService.registerUser(
                    request.email(), request.password(), request.firstName(), request.lastName(), roles
            );
            AuthResponse response = authService.createTokensForUser(newUser, httpRequest);

            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/update-user/{id}")
    public ResponseEntity<UserListDto> update(
            @PathVariable UUID id,
            @Valid @RequestBody UserUpdateDto updateDto
    ) {
        return ResponseEntity.ok(authService.updateUser(id, updateDto));
    }

    // -------------------------------
    // LOGIN
    // -------------------------------
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        try {
//            AuthResponse response = authService.authService.authenticate(request.email(), request.password());
            User user = authenticateAndGetUser(request.email(), request.password());
            AuthResponse response = authService.createTokensForUser(user, httpRequest);

            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.status(401).body("Login error: " + e.getMessage());
        }
    }

    // -------------------------------
    // REFRESH TOKEN
    // -------------------------------

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> body, HttpServletRequest request) {
        try {
            String fullRefreshToken = body.get("refreshToken");
            if (fullRefreshToken == null || fullRefreshToken.isBlank()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Refresh token required");
            }
            AuthResponse newTokens = authService.refreshToken(fullRefreshToken, request);
            return ResponseEntity.ok(newTokens);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(e.getMessage());
        }
    }

    // -------------------------------
    // REVOKE / LOGOUT
    // -------------------------------
    @PostMapping("/revoke")
    public ResponseEntity<?> revokeToken(@RequestBody RevokeRequest request) {
        try {
            refreshTokenService.revokeToken(request.refreshToken());
            return ResponseEntity.ok("Refresh token revoked");
        } catch (RuntimeException e) {
            return ResponseEntity.status(404).body(e.getMessage());
        }
    }

    @GetMapping("/me")
    public ResponseEntity<?> getAuthenticatedUser(@AuthenticationPrincipal Jwt jwt) {
        if (jwt == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User unauthorized");
        }

        UUID userId = UUID.fromString(jwt.getSubject());

        return userRepository.findById(userId)
                .map(user -> {
                    Map<String, Object> data = new HashMap<>();
                    data.put("id", user.getId());
                    data.put("email", user.getEmail());
                    data.put("fullName", user.getFirstName() + " " + user.getLastName());
                    return ResponseEntity.ok(data);
                })
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @PutMapping("/update-password")
    public ResponseEntity<?> updatePassword(
            @RequestBody ChangePasswordRequest request,
            @AuthenticationPrincipal Jwt jwt // Aquí Spring inyecta al usuario logueado
    ) {
        String subject = jwt.getSubject();
        UUID userId = UUID.fromString(subject);

        authService.changeUserPassword(userId, request.oldPassword(), request.newPassword());
        return ResponseEntity.ok("Pasword successfully udpated.");
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/admin/update-password")
    public ResponseEntity<?> updatePasswordByAdmin(
            @RequestBody AdminChangePasswordRequest request
    ) {
        authService.adminChangePassword(request.userId(), request.newPassword());
        return ResponseEntity.ok("Password updated successfully by administrator.");
    }

    @GetMapping("/users")
    public ResponseEntity<List<UserListDto>> getAllUsers(){
        return ResponseEntity.ok(authService.getAllUsers());
    }

    public User authenticateAndGetUser(String email, String rawPassword) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, rawPassword)
        );

        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("user not found."));
    }

    public static String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hashing token error.", e);
        }
    }
}
