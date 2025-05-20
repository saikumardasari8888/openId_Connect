package org.openid.connect.controller;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.openid.connect.model.User;
import org.openid.connect.repo.ZangoRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
public class TokenController {

    private final RegisteredClientRepository clientRepository;
    private final ZangoRepository userRepository;
    private final JWKSet jwkSet;

    // In-memory store for authorization codes
    private final Map<String, AuthCodeInfo> authCodes = new ConcurrentHashMap<>();

    /**
     * Store an authorization code
     */
    public void storeAuthCode(String code, String clientId, String redirectUri, String username) {
        authCodes.put(code, new AuthCodeInfo(clientId, redirectUri, username));
    }

    @PostMapping(
            value = "/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> token(
            @RequestParam("grant_type") String grantType,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam("client_id") String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            @RequestParam(value = "refresh_token", required = false) String refreshToken) { // Added refresh_token parameter

        // Validate client credentials
        RegisteredClient client = clientRepository.findByClientId(clientId);
        if (client == null) {
            return createErrorResponse("invalid_client", "Client not found");
        }

        // If client secret is provided, validate it
        if (clientSecret != null && !client.getClientSecret().equals(clientSecret)) {
            return createErrorResponse("invalid_client", "Invalid client credentials");
        }

        if ("authorization_code".equals(grantType)) {
            // Validate the authorization code
            AuthCodeInfo codeInfo = authCodes.get(code);
            if (codeInfo == null || !codeInfo.clientId.equals(clientId) ||
                    (redirectUri != null && !codeInfo.redirectUri.equals(redirectUri)) ||
                    codeInfo.expiresAt < System.currentTimeMillis()) {

                return createErrorResponse("invalid_grant", "Invalid or expired authorization code");
            }

            // Remove the used authorization code
            authCodes.remove(code);

            // Get the user associated with this code
            Optional<User> userOpt = userRepository.findByUsername(codeInfo.username);
            if (userOpt.isEmpty()) {
                return createErrorResponse("server_error", "User not found");
            }

            User user = userOpt.get();

            try {
                // Create access token and ID token
                String accessToken = generateAccessToken(clientId, user);
                String idToken = generateIdToken(clientId, user);
                String newRefreshToken = generateRefreshToken(clientId, user);

                Map<String, Object> response = new HashMap<>();
                response.put("access_token", accessToken);
                response.put("token_type", "Bearer");
                response.put("expires_in", 3600); // 1 hour
                response.put("id_token", idToken);
                response.put("refresh_token", newRefreshToken);

                return ResponseEntity.ok(response);
            } catch (Exception e) {
                e.printStackTrace();
                return createErrorResponse("server_error", "Failed to generate tokens: " + e.getMessage());
            }
        } else if ("refresh_token".equals(grantType)) {
            // Use the refreshToken parameter instead of trying to get it from request
            if (refreshToken == null || refreshToken.isEmpty()) {
                return createErrorResponse("invalid_request", "Refresh token is required");
            }

            // Here you would validate the refresh token
            // For now, we'll just create new tokens as an example
            try {
                // Find a user for this client (this is simplified)
                Optional<User> userOpt = userRepository.findAll().stream().findFirst();
                if (userOpt.isEmpty()) {
                    return createErrorResponse("server_error", "No users found");
                }

                User user = userOpt.get();

                // Create new access token and ID token
                String accessToken = generateAccessToken(clientId, user);
                String idToken = generateIdToken(clientId, user);
                String newRefreshToken = generateRefreshToken(clientId, user);

                Map<String, Object> response = new HashMap<>();
                response.put("access_token", accessToken);
                response.put("token_type", "Bearer");
                response.put("expires_in", 3600); // 1 hour
                response.put("id_token", idToken);
                response.put("refresh_token", newRefreshToken);

                return ResponseEntity.ok(response);
            } catch (Exception e) {
                e.printStackTrace();
                return createErrorResponse("server_error", "Failed to refresh tokens");
            }
        } else {
            return createErrorResponse("unsupported_grant_type", "Unsupported grant type");
        }
    }

    private ResponseEntity<Map<String, Object>> createErrorResponse(String error, String description) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", error);
        response.put("error_description", description);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    private String generateAccessToken(String clientId, User user) throws Exception {
        // Get the RSA key for signing
        RSAKey rsaKey = (RSAKey) jwkSet.getKeys().get(0);
        JWSSigner signer = new RSASSASigner(rsaKey.toRSAPrivateKey());

        // Current time and expiration
        Date now = new Date();
        Date expiryTime = new Date(now.getTime() + 3600 * 1000); // 1 hour

        // Create JWT claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(user.getId().toString())
                .issuer("https://openid-connect.onrender.com") // Make sure this matches your config
                .audience(clientId)
                .expirationTime(expiryTime)
                .issueTime(now)
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", "openid profile email")
                .claim("name", user.getFullName())
                .claim("email", user.getEmail())
                .build();

        // Sign the JWT
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                claims);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    private String generateIdToken(String clientId, User user) throws Exception {
        // Get the RSA key for signing
        RSAKey rsaKey = (RSAKey) jwkSet.getKeys().get(0);
        JWSSigner signer = new RSASSASigner(rsaKey.toRSAPrivateKey());

        // Current time and expiration
        Date now = new Date();
        Date expiryTime = new Date(now.getTime() + 3600 * 1000); // 1 hour

        // Create JWT claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(user.getId().toString())
                .issuer("https://openid-connect.onrender.com") // Make sure this matches your config
                .audience(clientId)
                .expirationTime(expiryTime)
                .issueTime(now)
                .claim("preferred_username", user.getUsername())
                .claim("email", user.getEmail())
                .claim("email_verified", user.isEmailVerified())
                .claim("name", user.getFullName())
                .build();

        // Sign the JWT
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                claims);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    private String generateRefreshToken(String clientId, User user) {
        // For a real implementation, you should:
        // 1. Generate a secure refresh token
        // 2. Store it with an association to the user and client
        // 3. Set a longer expiration

        return UUID.randomUUID().toString();
    }

    // Helper class to store authorization code information
    public static class AuthCodeInfo {
        String clientId;
        String redirectUri;
        String username;
        long expiresAt;

        AuthCodeInfo(String clientId, String redirectUri, String username) {
            this.clientId = clientId;
            this.redirectUri = redirectUri;
            this.username = username;
            // Set expiration to 10 minutes from now
            this.expiresAt = System.currentTimeMillis() + (10 * 60 * 1000);
        }
    }
}