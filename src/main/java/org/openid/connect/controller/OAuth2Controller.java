package org.openid.connect.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Map;
import java.util.UUID;

@Controller
@RequestMapping("/oauth2")
@RequiredArgsConstructor
public class OAuth2Controller {

    private final OAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository clientRepository;

    @GetMapping("/authorize")
    public String authorize(
            @RequestParam Map<String, String> parameters,
            HttpServletRequest request,
            HttpSession session,
            Model model) {

        // Store OAuth2 authorization request parameters in session
        session.setAttribute("oauth2_auth_request", parameters);

        // Add the client_id to the model so we can display it on the consent page
        model.addAttribute("clientId", parameters.get("client_id"));
        model.addAttribute("scopes", parameters.getOrDefault("scope", "").split(" "));

        // Check if user is already authenticated
        if (request.getUserPrincipal() == null) {
            // User not authenticated, redirect to login
            return "redirect:/auth/login?redirect=" + request.getRequestURL().toString() + "?" + request.getQueryString();
        } else {
            // User is authenticated, show consent page
            return "consent";
        }
    }

    @PostMapping("/authorize/confirm")
    public void confirmAuthorization(
            HttpServletRequest request,
            HttpServletResponse response,
            HttpSession session) throws IOException {

        @SuppressWarnings("unchecked")
        Map<String, String> authParams = (Map<String, String>) session.getAttribute("oauth2_auth_request");

        if (authParams != null) {
            // Create the authorization response with the authorization code
            String redirectUri = authParams.get("redirect_uri");
            String state = authParams.getOrDefault("state", "");

            // In a real application, you would generate an authorization code here
            String authCode = generateAuthorizationCode(authParams.get("client_id"), request.getUserPrincipal().getName());

            // Build the redirect URL with the authorization code
            String redirectUrl = redirectUri +
                    "?code=" + authCode +
                    (state.isEmpty() ? "" : "&state=" + state);

            // Clear the authorization request from the session
            session.removeAttribute("oauth2_auth_request");

            // Redirect to the client's redirect URI
            response.sendRedirect(redirectUrl);
        } else {
            // Handle error - missing parameters
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid authorization request");
        }
    }

    private String generateAuthorizationCode(String clientId, String username) {
        // This is a simplified example - in a real application, you would:
        // 1. Generate a secure random code
        // 2. Store it with associated client_id, redirect_uri, scopes, and username
        // 3. Set a short expiration time

        // For demo purposes, using a UUID-based code
        String code = UUID.randomUUID().toString();

        // In a real implementation, you would store this code in your authorization service
        // authorizationService.save(code, clientId, username, ...);

        return code;
    }
}