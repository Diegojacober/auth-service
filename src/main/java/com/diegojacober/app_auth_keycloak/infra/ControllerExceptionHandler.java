package com.diegojacober.app_auth_keycloak.infra;

import static org.springframework.http.HttpStatus.*;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.HttpClientErrorException.Unauthorized;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import com.diegojacober.app_auth_keycloak.dtos.ApiErrors;
import com.diegojacober.app_auth_keycloak.dtos.ExceptionDTO;
import com.diegojacober.app_auth_keycloak.exceptions.IncorrectCredentialsException;

@RestControllerAdvice
public class ControllerExceptionHandler {
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Object> methodNotSupportedException(Exception exception) {
        ExceptionDTO exceptionDTO = new ExceptionDTO(exception.getMessage(), "405");

        return ResponseEntity.status(METHOD_NOT_ALLOWED).body(exceptionDTO);
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<Object> notFoundException(Exception exception) {
        return ResponseEntity.notFound().build();
    }

    @ExceptionHandler(Unauthorized.class)
    @ResponseStatus(UNAUTHORIZED)
    public ApiErrors unauthorizedException(MethodArgumentNotValidException ext) {
        List<String> errors = ext.getBindingResult().getAllErrors().stream().map(erro -> erro.getDefaultMessage())
                .collect(Collectors.toList());

        return new ApiErrors(errors);
    }

    @ExceptionHandler(IncorrectCredentialsException.class)
    @ResponseStatus(UNAUTHORIZED)
    public ResponseEntity<Object> handleIncorrectCredentialsExcpetion(IncorrectCredentialsException ext) {
        ExceptionDTO exceptionDTO = new ExceptionDTO(ext.getMessage(), "401");

        return ResponseEntity.status(UNAUTHORIZED).body(exceptionDTO);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(BAD_REQUEST)
    public ApiErrors handleMethodNotValidException(MethodArgumentNotValidException ext) {
        List<String> errors = ext.getBindingResult().getAllErrors().stream().map(erro -> erro.getDefaultMessage())
                .collect(Collectors.toList());

        return new ApiErrors(errors);
    }
}
