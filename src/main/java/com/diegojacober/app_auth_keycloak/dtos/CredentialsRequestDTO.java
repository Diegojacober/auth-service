package com.diegojacober.app_auth_keycloak.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.*;

@Data
@AllArgsConstructor
@Builder
public class CredentialsRequestDTO {

    @JsonProperty("temporary")
    private boolean temporary;

    @JsonProperty("type")
    private String type;

    @JsonProperty("value")
    private String value;
}
