package com.diegojacober.app_auth_keycloak.dtos;

import java.util.Arrays;
import java.util.List;

import lombok.Getter;
public class ApiErrors {

    @Getter
    private List<String> errors;

    public ApiErrors(String msgError) {
        this.errors = Arrays.asList(msgError);
    }

    public ApiErrors(List<String> errors) {
        this.errors = errors;
    }
}