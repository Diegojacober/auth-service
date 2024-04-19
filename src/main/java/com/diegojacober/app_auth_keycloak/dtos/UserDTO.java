package com.diegojacober.app_auth_keycloak.dtos;

import java.util.Map;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {
    private Map<String, String> attributes;

    @NotNull(message = "Preencha o campo password")
    @Size(max = 32, message = "o campo password deve ter no máximo 32 caracteres")
    private String password;

    @NotNull(message = "Preencha o campo firtName")
    @Size(max = 32, message = "o campo firstname deve ter no máximo 32 caracteres")
    private String firstName;

    @NotNull(message = "Preencha o campo lastName")
    @Size(max = 32, message = "o campo lastName deve ter no máximo 32 caracteres")
    private String lastName;
}
