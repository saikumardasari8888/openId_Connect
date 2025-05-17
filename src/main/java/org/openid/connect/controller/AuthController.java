package org.openid.connect.controller;

import com.nimbusds.jose.jwk.JWKSet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.openid.connect.model.User;
import org.openid.connect.repo.ZangoRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Controller
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authManager;
    private final ZangoRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWKSet jwkSet;


    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/register")
    public String registerPage(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute User user, Model model) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        model.addAttribute("message", "User registered successfully. Please login.");
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model, Principal principal) {
        model.addAttribute("username", principal.getName());
        return "dashboard";
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        // Invalidate the session
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        // Clear authentication
        SecurityContextHolder.clearContext();

        // Optionally delete cookies
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                cookie.setMaxAge(0);
                cookie.setPath("/");
                response.addCookie(cookie);
            }
        }

        return "redirect:/login?logout";
    }
    @GetMapping("/userinfo")
    @ResponseBody
    public Map<String, Object> getUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();

        Optional<User> userOpt = userRepository.findByUsername(username);
        Map<String, Object> userInfo = new HashMap<>();

        if (userOpt.isPresent()) {
            User user = userOpt.get();
            userInfo.put("sub", user.getId().toString());
            userInfo.put("preferred_username", user.getUsername());
            userInfo.put("email", user.getUsername());
            userInfo.put("email_verified", true);
            // Add additional user claims as needed
        }

        return userInfo;
    }

    @GetMapping("/.well-known/jwks.json")
    @ResponseBody
    public Map<String, Object> jwks() {
        return jwkSet.toJSONObject();
    }
}

