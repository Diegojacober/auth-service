package com.diegojacober.app_auth_keycloak.dtos;

import java.util.Map;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Builder; 
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CreateUserKeycloak {

    @JsonProperty("attributes")
    private Map<String, String> attributes;
    
    @JsonProperty("credentials")
    private List<CredentialsRequestDTO> credentials;

    @JsonProperty("username")
    private String username;

    @JsonProperty("firstName")
    private String firstName;

    @JsonProperty("lastName")
    private String lastName;

    @JsonProperty("email")
    private String email;

    @JsonProperty("emailVerified")
    private boolean emailVerified;

    @JsonProperty("enabled")
    private boolean enabled;
}
