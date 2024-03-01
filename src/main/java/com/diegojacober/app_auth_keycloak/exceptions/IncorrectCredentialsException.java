package com.diegojacober.app_auth_keycloak.exceptions;

public class IncorrectCredentialsException extends Exception {
    public IncorrectCredentialsException(String msg) {
        super(msg);
    }
}
