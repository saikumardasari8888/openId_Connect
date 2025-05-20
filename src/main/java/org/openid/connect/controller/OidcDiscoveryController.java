package org.openid.connect.controller;

import com.nimbusds.jose.jwk.JWKSet;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/.well-known")
@RequiredArgsConstructor
public class OidcDiscoveryController {

    private final JWKSet jwkSet;
    private final String issuerUrl = "https://openid-connect.onrender.com";

    @GetMapping("/openid-configuration")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> discovery() {
        Map<String, Object> config = new HashMap<>();

        // OIDC Discovery document properties
        config.put("issuer", issuerUrl);
        config.put("authorization_endpoint", issuerUrl + "/oauth2/authorize");
        config.put("token_endpoint", issuerUrl + "/oauth2/token");
        config.put("userinfo_endpoint", issuerUrl + "/userinfo");
        config.put("jwks_uri", issuerUrl + "/.well-known/jwks.json");
        config.put("end_session_endpoint", issuerUrl + "/connect/logout");

        // Add supported scopes
        config.put("scopes_supported", Arrays.asList("openid", "profile", "email"));

        // Add supported response types
        config.put("response_types_supported", Arrays.asList("code"));

        // Add supported grant types
        config.put("grant_types_supported", Arrays.asList("authorization_code", "refresh_token"));

        // Add supported subject types
        config.put("subject_types_supported", Arrays.asList("public"));

        // Add supported signing algorithms
        config.put("id_token_signing_alg_values_supported", Arrays.asList("RS256"));

        // Add supported claims
        config.put("claims_supported", Arrays.asList(
                "sub", "iss", "auth_time", "name", "given_name", "family_name",
                "preferred_username", "email", "email_verified"
        ));

        return ResponseEntity.ok(config);
    }

    @GetMapping(value = "/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> jwks() {
        return jwkSet.toJSONObject();
    }
}