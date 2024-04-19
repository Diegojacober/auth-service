package com.diegojacober.app_auth_keycloak.controller;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.diegojacober.app_auth_keycloak.dtos.CreateUserKeycloak;
import com.diegojacober.app_auth_keycloak.dtos.CredentialsRequestDTO;
import com.diegojacober.app_auth_keycloak.dtos.LoginDTO;
import com.diegojacober.app_auth_keycloak.dtos.RefreshDTO;
import com.diegojacober.app_auth_keycloak.dtos.RequestNewRoleDTO;
import com.diegojacober.app_auth_keycloak.dtos.RoleDTO;
import com.diegojacober.app_auth_keycloak.dtos.UserDTO;
import com.diegojacober.app_auth_keycloak.dtos.enums.Role;
import com.diegojacober.app_auth_keycloak.exceptions.IncorrectBodyException;
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

    @PostMapping("/users")
    @PreAuthorize("hasRole('instructor')")
    public ResponseEntity<String> createUser(@RequestHeader HttpHeaders headers, @RequestBody @Valid UserDTO dto)
            throws Exception {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt user = (Jwt) authentication.getPrincipal();

        String token = user.getTokenValue();
        headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));

        var credential = CredentialsRequestDTO
                .builder()
                .temporary(false)
                .type("password")
                .value(dto.getPassword())
                .build();

        List<CredentialsRequestDTO> credentials = new ArrayList<>();
        credentials.add(credential);

        var userKeycloak = CreateUserKeycloak
        .builder()
        .attributes(dto.getAttributes())
        .lastName(dto.getLastName())
        .firstName(dto.getFirstName())
        .username(dto.getFirstName() + "_" + dto.getLastName())
        .credentials(credentials)
        .email(dto.getFirstName() + dto.getLastName() + "@email.com")
        .emailVerified(true)
        .enabled(true)
        .build();

        // System.out.println(userKeycloak);
        try {
            var t =  authServiceClient.createUser(headers, userKeycloak);
            return ResponseEntity.ok().body("Ok");
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        } catch (feign.RetryableException ex) {
            System.out.println(ex.getMessage());
        }
        return null;
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

    @GetMapping("/users")
    @PreAuthorize("hasRole('instructor')")
    public Object getUsers(@RequestHeader HttpHeaders headers) throws IncorrectCredentialsException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt user = (Jwt) authentication.getPrincipal();

        String token = user.getTokenValue();

        headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));

        try {
            return authServiceClient.getUsers(headers);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @GetMapping("/users/{userId}/roles")
    @PreAuthorize("hasRole('instructor')")

    public Object getUserRoles(@PathVariable String userId) throws IncorrectCredentialsException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt user = (Jwt) authentication.getPrincipal();
        String token = user.getTokenValue();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));

        try {
            return authServiceClient.getUserRoles(userId, headers);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @PostMapping("/users/{userId}/roles")
    @PreAuthorize("hasRole('instructor')")
    public Object postUserRole(@PathVariable String userId, @RequestBody @Valid RequestNewRoleDTO dto)
            throws IncorrectBodyException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt user = (Jwt) authentication.getPrincipal();
        String token = user.getTokenValue();
        HttpHeaders headers = new HttpHeaders();

        System.out.println(dto.getRole());
        String idRole = "";
        if (dto.getRole().equals(Role.APPRENTICE)) {
            idRole = "257afb7f-7930-4dd3-a768-ffef905767db";
        } else if (dto.getRole().equals(Role.INSTRUCTOR)) {
            idRole = "47aaded2-ad99-43e5-b222-60be9449586d";
        }

        RoleDTO roleDTO = RoleDTO.builder()
                .composite(false)
                .clientRole(true)
                .name(dto.getRole().toString())
                .id(idRole)
                .containerId("753b9b9b-5106-474d-b11f-cc4f8ba03fcd")
                .build();
        try {

            headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));
            List<RoleDTO> roles = Arrays.asList(roleDTO);
            return authServiceClient.postUserRoles(userId, headers, roles);
        } catch (FeignException ex) {
            System.out.println(ex.getMessage());
            throw new IncorrectBodyException("campos inválidos");
        }
    }

    @GetMapping("/roles")
    @PreAuthorize("hasRole('instructor')")
    public Object getRoles() throws IncorrectCredentialsException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Jwt user = (Jwt) authentication.getPrincipal();

            String token = user.getTokenValue();
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));
            return authServiceClient.getClientRoles(headers);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }

    @GetMapping("/users/{role}")
    @PreAuthorize("hasRole('instructor')")
    public Object getUsersByRole(@PathVariable String role) throws IncorrectCredentialsException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Jwt user = (Jwt) authentication.getPrincipal();
            String token = user.getTokenValue();
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.AUTHORIZATION, ("Bearer " + token));
            return authServiceClient.getUsersByRole(role, headers);
        } catch (FeignException.Unauthorized ex) {
            throw new IncorrectCredentialsException("Credenciais incorretas.");
        }
    }
}
