package com.diegojacober.app_auth_keycloak;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@EnableFeignClients
@SpringBootApplication
public class AppAuthKeycloakApplication {

	public static void main(String[] args) {
		SpringApplication.run(AppAuthKeycloakApplication.class, args);
	}

}
