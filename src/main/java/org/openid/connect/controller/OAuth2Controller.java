package org.openid.connect.controller;

import lombok.RequiredArgsConstructor;
import org.openid.connect.model.User;
import org.openid.connect.repo.ZangoRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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
import java.security.Principal;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Controller
@RequestMapping("/oauth2")
@RequiredArgsConstructor
public class OAuth2Controller {

    private final OAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository clientRepository;
    private final ZangoRepository userRepository;
    private final TokenController tokenController;

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
        model.addAttribute("redirectUri", parameters.get("redirect_uri"));
        model.addAttribute("state", parameters.getOrDefault("state", ""));

        // Check if user is already authenticated
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() ||
                "anonymousUser".equals(authentication.getName())) {
            // User not authenticated, redirect to login
            return "redirect:/auth/login?redirect=" + request.getRequestURL().toString() + "?" + request.getQueryString();
        } else {
            // User is authenticated, show consent page or auto-approve
            // For SAP integration, we might want to auto-approve
            // return "consent";

            // Auto-approve for SAP integration
            String clientId = parameters.get("client_id");
            String redirectUri = parameters.get("redirect_uri");
            String state = parameters.getOrDefault("state", "");

            // Generate authorization code
            String authCode = generateAuthorizationCode(clientId, authentication.getName(), redirectUri);

            // Store the authorization code info in TokenController
            tokenController.storeAuthCode(authCode, clientId, redirectUri, authentication.getName());

            // Build the redirect URL with the authorization code
            String redirectUrl = redirectUri +
                    "?code=" + authCode +
                    (state.isEmpty() ? "" : "&state=" + state);

            // Redirect to the client's redirect URI
            try {
                HttpServletResponse response = ((HttpServletResponse) request.getAttribute("response"));
                if (response != null) {
                    response.sendRedirect(redirectUrl);
                    return null;
                } else {
                    return "redirect:" + redirectUrl;
                }
            } catch (IOException e) {
                return "error";
            }
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

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();

            // Generate an authorization code
            String authCode = generateAuthorizationCode(authParams.get("client_id"), username, redirectUri);

            // Store the authorization code info in TokenController
            tokenController.storeAuthCode(authCode, authParams.get("client_id"), redirectUri, username);

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

    private String generateAuthorizationCode(String clientId, String username, String redirectUri) {
        // Generate a secure random code
        String code = UUID.randomUUID().toString();

        // Now the authorization code is stored by the TokenController
        // No need to store it here again

        return code;
    }
}