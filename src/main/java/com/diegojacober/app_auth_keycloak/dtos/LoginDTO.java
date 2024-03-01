package com.diegojacober.app_auth_keycloak.dtos;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginDTO {
    
    @NotNull(message = "Preencha o campo username")
    @Size(max = 32, message = "O username deve ter no máximo 32 caracteres")
    private String username;
    
    @NotNull(message = "Preencha o campo senha")
    @Size(min = 6, max = 32,message = "O senha deve ter entre 6 a 32 caracteres")
    private String password;
}
