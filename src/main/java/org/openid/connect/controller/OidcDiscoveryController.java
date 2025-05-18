package org.openid.connect.controller;

import lombok.RequiredArgsConstructor;
import org.openid.connect.repo.ZangoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/.well-known")
public class OidcDiscoveryController {

    @Autowired
    private  OAuth2AuthorizationService authorizationService;

    @Autowired
    private  ZangoRepository userRepository;

    @GetMapping("/openid-configuration")
    public ModelAndView discovery() {
        ModelAndView mav = new ModelAndView("oidc-discovery");
        // OIDC Discovery document properties
        mav.addObject("issuer", "https://openid-connect.onrender.com");
        mav.addObject("authorization_endpoint", "https://openid-connect.onrender.com/oauth2/authorize");
        mav.addObject("token_endpoint", "https://openid-connect.onrender.com/oauth2/token");
        mav.addObject("userinfo_endpoint", "https://openid-connect.onrender.com/userinfo");
        mav.addObject("jwks_uri", "https://openid-connect.onrender.com/.well-known/jwks.json");

        // Add supported scopes
        mav.addObject("scopes_supported", new String[]{"openid", "profile", "email"});

        // Add supported response types
        mav.addObject("response_types_supported", new String[]{"code"});

        // Add supported grant types
        mav.addObject("grant_types_supported", new String[]{"authorization_code", "refresh_token"});

        // Add supported subject types
        mav.addObject("subject_types_supported", new String[]{"public"});

        // Add supported signing algorithms
        mav.addObject("id_token_signing_alg_values_supported", new String[]{"RS256"});

        return mav;
    }

    @GetMapping("/jwks.json")
    public ModelAndView jwks() {
        ModelAndView mav = new ModelAndView("jwks");
        // The JWK Set will be injected by a controller advice
        return mav;
    }
}
