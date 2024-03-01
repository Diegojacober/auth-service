package com.diegojacober.app_auth_keycloak.dtos;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RefreshDTO {
    @NotNull(message = "Preencha o campo refresh_token")
    private String refresh_token;
}
    
