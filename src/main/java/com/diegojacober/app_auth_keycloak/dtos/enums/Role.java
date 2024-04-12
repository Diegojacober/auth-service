package com.diegojacober.app_auth_keycloak.dtos.enums;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@JsonDeserialize(using = RoleDeserializer.class)
public enum Role {
    APPRENTICE,
    INSTRUCTOR
}
