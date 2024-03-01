package com.diegojacober.app_auth_keycloak.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.diegojacober.app_auth_keycloak.dtos.LoginDTO;
import com.diegojacober.app_auth_keycloak.dtos.RefreshDTO;
import com.diegojacober.app_auth_keycloak.exceptions.IncorrectCredentialsException;
import com.diegojacober.app_auth_keycloak.infra.OpenFeign.AuthServiceClient;

import feign.FeignException;
import jakarta.validation.Valid;

@RequestMapping("/auth")
@RestController
public class AuthController {

    @Autowired
    private AuthServiceClient authServiceClient;

    @PostMapping("/login")
    public ResponseEntity<String> accessToken(@RequestBody @Valid LoginDTO user) throws IncorrectCredentialsException {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", "back-end");
        formData.add("username", user.getUsername());
        formData.add("password", user.getPassword());
        formData.add("grant_type", "password");
        formData.add("client_secret", "6gwYLM1MOMfYG6cX1lZgjPkOeauPTKSZ");

        try {
            return authServiceClient.getToken(formData);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<String> refreshToken(@RequestBody @Valid RefreshDTO dto)
            throws IncorrectCredentialsException {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", "back-end");
        formData.add("refresh_token", dto.getRefresh_token());
        formData.add("grant_type", "refresh_token");
        formData.add("client_secret", "6gwYLM1MOMfYG6cX1lZgjPkOeauPTKSZ");

        try {
            return authServiceClient.getToken(formData);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        } catch (FeignException.FeignClientException ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @GetMapping("/userinfo")
    public Object getUserInfo() throws IncorrectCredentialsException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt user = (Jwt) authentication.getPrincipal();

        String token = user.getTokenValue();

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", "back-end");
        formData.add("scope", "openid");
        formData.add("grant_type", "client_credentials");
        formData.add("client_secret", "6gwYLM1MOMfYG6cX1lZgjPkOeauPTKSZ");

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));

        try {
        return authServiceClient.getUserInfo(formData, headers);
        } catch (FeignException.Unauthorized ex) {
        throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

}
