package com.diegojacober.app_auth_keycloak.infra.OpenFeign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

import feign.Headers;

@FeignClient(name = "auth-service", url = "http://localhost:8181")
public interface AuthServiceClient {
   @PostMapping(value = "/realms/test/protocol/openid-connect/token")
   @Headers("Content-Type: application/x-www-form-urlencoded")
   ResponseEntity<String> getToken(@RequestBody MultiValueMap<String, String> formData);

   @PostMapping(value = "/realms/test/protocol/openid-connect/userinfo")
   @Headers("Content-Type: application/x-www-form-urlencoded")
   ResponseEntity<String> getUserInfo(@RequestBody MultiValueMap<String, String> formData, @RequestHeader HttpHeaders headers);
}
