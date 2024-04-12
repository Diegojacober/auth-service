package com.diegojacober.app_auth_keycloak.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RoleDTO {
    private String id;
    private String name;
    private boolean composite;
    private boolean clientRole;
    private String containerId;
}

