package com.diegojacober.app_auth_keycloak.dtos;

import com.diegojacober.app_auth_keycloak.dtos.enums.Role;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RequestNewRoleDTO {
    @NotNull(message = "Insira uma permissão válida")
    private Role role;
}
