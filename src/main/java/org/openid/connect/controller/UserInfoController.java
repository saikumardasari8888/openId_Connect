package org.openid.connect.controller;

import lombok.RequiredArgsConstructor;
import org.openid.connect.model.User;
import org.openid.connect.repo.ZangoRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class UserInfoController {

    private final ZangoRepository userRepository;

    @GetMapping("/userinfo")
    public ResponseEntity<Map<String, Object>> getUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).build();
        }

        String username = authentication.getName();
        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isEmpty()) {
            return ResponseEntity.status(404).build();
        }

        User user = userOpt.get();
        Map<String, Object> userInfo = new HashMap<>();

        // Standard OIDC claims
        userInfo.put("sub", user.getId().toString());
        userInfo.put("name", user.getFullName());
        userInfo.put("preferred_username", user.getUsername());
        userInfo.put("email", user.getEmail());
        userInfo.put("email_verified", user.isEmailVerified());

        // Add phone if available
        if (user.getPhoneNumber() != null && !user.getPhoneNumber().isEmpty()) {
            userInfo.put("phone_number", user.getPhoneNumber());
            userInfo.put("phone_number_verified", user.isPhoneVerified());
        }

        // Add any custom attributes from the user object
        if (user.getAttributes() != null && !user.getAttributes().isEmpty()) {
            userInfo.putAll(user.getAttributes());
        }

        return ResponseEntity.ok(userInfo);
    }
}