package org.openid.connect.controller;

import lombok.RequiredArgsConstructor;
import org.openid.connect.model.User;
import org.openid.connect.repo.ZangoRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.http.HttpStatus;
import org.springframework.util.ObjectUtils;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.text.ParseException;
import java.util.Date;
import java.util.TimeZone;
import java.util.HashMap;
import java.util.Map;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class UserInfoController {

    private final ZangoRepository userRepository;


    @PostMapping("/convert-to-utc/{Date}")
    public ResponseEntity<Map<String, Object>> convertToUTC(@PathVariable("Date") String Date) {
        Map<String, Object> response = new HashMap<>();
        
        try {
            Date utcDate = convertStringTimezoneToDate(request.getDatetime());            
            return ResponseEntity.ok(utcFormat);
            
        } catch (Exception e) {            
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    public static Date convertStringTimezoneToDate(String datetime) {
        if (ObjectUtils.isEmpty(datetime)) {
            return new Date();
        }
        try {
            // Handle the timezone offset format (+0000, -0500, etc.)
            DateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
            format.setTimeZone(TimeZone.getTimeZone("UTC"));
            return format.parse(datetime);
        } catch (ParseException e) {
            return new Date();
        }
    }

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
