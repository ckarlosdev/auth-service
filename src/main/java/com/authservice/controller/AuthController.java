package com.authservice.controller;

import com.authservice.dto.AuthResponse;
import com.authservice.model.RefreshToken;
import com.authservice.model.User;
import com.authservice.repository.RefreshTokenRepository;
import com.authservice.repository.UserRepository;
import com.authservice.service.AuthService;
import com.authservice.service.JwtService;
import com.authservice.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

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
    record RegisterRequest(String email, String password, String firstName, String lastName) {}
    record RefreshRequest(String refreshToken){}
    record RevokeRequest(String refreshToken){}

    // -------------------------------
    // REGISTER
    // -------------------------------
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
        try {
            User newUser = authService.registerUser(
                    request.email(), request.password(), request.firstName(), request.lastName()
            );
//            AuthResponse response = authService.authenticate(request.email(), request.password());
            AuthResponse response = createTokensForUser(newUser, httpRequest);

            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    // -------------------------------
    // LOGIN
    // -------------------------------
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        try {
//            AuthResponse response = authService.authenticate(request.email(), request.password());
            User user = authenticateAndGetUser(request.email(), request.password());
            AuthResponse response = createTokensForUser(user, httpRequest);

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
            String rawRefreshToken = body.get("refreshToken");
            AuthResponse newTokens = authService.refreshToken(rawRefreshToken, request);
            return ResponseEntity.ok(newTokens);
        } catch (RuntimeException e) {
            return ResponseEntity.status(401).body(e.getMessage());
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

    // -------------------------------
    // crea Access + Refresh tokens y guarda refresh en DB
    // -------------------------------
    private AuthResponse createTokensForUser(User user, HttpServletRequest httpRequest) {
        String accessToken = generateAccessToken(user);

        String rawRefreshToken = UUID.randomUUID().toString();
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setId(UUID.randomUUID());
        refreshToken.setUser(user);
        refreshToken.setTokenHash(passwordEncoder.encode(rawRefreshToken));
        refreshToken.setExpiresAt(Instant.now().plusSeconds(60 * 60 * 24 * 7)); // 7 días
        refreshToken.setIpAddress(httpRequest.getRemoteAddr());

        refreshTokenRepository.save(refreshToken);

        return new AuthResponse(accessToken, rawRefreshToken, user.getId());
    }

    public String generateAccessToken(User user) {
        return jwtService.generateToken(user.getId(), user.getEmail());
    }

    public User authenticateAndGetUser(String email, String rawPassword) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, rawPassword)
        );

        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado."));
    }

    public static String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error al hashear el token", e);
        }
    }
}
