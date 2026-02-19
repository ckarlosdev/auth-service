package com.authservice.service;

import com.authservice.dto.AuthResponse;
import com.authservice.model.RefreshToken;
import com.authservice.model.User;
import com.authservice.repository.RefreshTokenRepository;
import com.authservice.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class AuthService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       AuthenticationManager authenticationManager,
                       JwtService jwtService,
                       RefreshTokenRepository refreshTokenRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public User registerUser(String email, String rawPassword, String firstName, String lastName) {
        if (userRepository.findByEmail(email).isPresent()) {
            throw new RuntimeException("Email already used.");
        }

        User newUser = new User();
//        newUser.setId(UUID.randomUUID().toString());
        newUser.setEmail(email);
        newUser.setFirstName(firstName);
        newUser.setLastName(lastName);

        String hashedPassword = passwordEncoder.encode(rawPassword);
        newUser.setPasswordHash(hashedPassword);

        return userRepository.save(newUser);
    }

    public AuthResponse authenticate(String email, String rawPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found."));

        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            throw new RuntimeException("Valid credentials.");
        }

        String token = jwtService.generateToken(user.getId(), user.getEmail());
        return new AuthResponse(token, "", user.getId());
    }


    @Override
    public UserDetails loadUserByUsername(String identifier) throws UsernameNotFoundException {
        try {
            UUID userId = UUID.fromString(identifier);
            return userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + identifier));
        } catch (IllegalArgumentException e) {
            return userRepository.findByEmail(identifier)
                    .orElseThrow(() -> new UsernameNotFoundException("User nor found with email: " + identifier));
        }
    }

    public AuthResponse createTokensForUser(User user, HttpServletRequest httpRequest) {

        // 1️⃣ Access Token
        String accessToken = jwtService.generateToken(user.getId(), user.getEmail());

        // 2️⃣ Generar ID del refresh token
        UUID tokenId = UUID.randomUUID();

        // 3️⃣ Generar secret
        String rawSecret = UUID.randomUUID().toString();

        // 4️⃣ Hashear secret
        String hashedSecret = passwordEncoder.encode(rawSecret);

        // 5️⃣ Crear entidad
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setId(tokenId);
        refreshToken.setUser(user);
        refreshToken.setTokenHash(hashedSecret);
        refreshToken.setCreatedAt(Instant.now());
        refreshToken.setExpiresAt(Instant.now().plusSeconds(60 * 60 * 24 * 7));
        refreshToken.setIpAddress(httpRequest.getRemoteAddr());

        refreshTokenRepository.save(refreshToken);

        // 6️⃣ Construir refresh token final
        String finalRefreshToken = tokenId + "." + rawSecret;

        return new AuthResponse(accessToken, finalRefreshToken, user.getId());
    }

    public AuthResponse refreshToken(String fullRefreshToken, HttpServletRequest request) {

        if (fullRefreshToken == null || !fullRefreshToken.contains(".")) {
            throw new RuntimeException("invalid refresh token.");
        }

        String[] parts = fullRefreshToken.split("\\.");
        UUID tokenId = UUID.fromString(parts[0]);
        String rawSecret = parts[1];

        RefreshToken refreshToken = refreshTokenRepository.findById(tokenId)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        if (!passwordEncoder.matches(rawSecret, refreshToken.getTokenHash())) {
            throw new RuntimeException("Refresh token invalid");
        }

        if (refreshToken.getRevokedAt() != null) {
            throw new RuntimeException("Refresh token revoked");
        }

        if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
            throw new RuntimeException("Refresh token expired");
        }

        // Rotación (one-time use)
        refreshToken.setRevokedAt(Instant.now());
        refreshTokenRepository.save(refreshToken);

        return createTokensForUser(refreshToken.getUser(), request);
    }

    public void changeUserPassword(UUID userId, String oldPassword, String newPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found."));

        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new BadCredentialsException("Current password wrong.");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

}
