package com.diegojacober.app_auth_keycloak.infra.OpenFeign;

import java.util.List;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

import com.diegojacober.app_auth_keycloak.dtos.CreateUserKeycloak;
import com.diegojacober.app_auth_keycloak.dtos.RoleDTO;

import feign.Headers;

@FeignClient(name = "auth-service", url = "http://localhost:8181")
public interface AuthServiceClient {
   @PostMapping(value = "/realms/test/protocol/openid-connect/token")
   @Headers("Content-Type: application/x-www-form-urlencoded")
   ResponseEntity<String> getToken(@RequestBody MultiValueMap<String, String> formData);

   @PostMapping(value = "/realms/test/protocol/openid-connect/userinfo")
   @Headers("Content-Type: application/x-www-form-urlencoded")
   ResponseEntity<String> getUserInfo(@RequestBody MultiValueMap<String, String> formData,
         @RequestHeader HttpHeaders headers);

   @GetMapping(value = "/admin/realms/test/clients/753b9b9b-5106-474d-b11f-cc4f8ba03fcd/roles")
   @Headers("Content-Type: application/x-www-form-urlencoded")
   ResponseEntity<String> getClientRoles(@RequestHeader HttpHeaders headers);

   @GetMapping(value = "/admin/realms/test/users")
   @Headers("Content-Type: application/x-www-form-urlencoded")
   ResponseEntity<String> getUsers(@RequestHeader HttpHeaders headers);

   @GetMapping(value = "/admin/realms/test/users/{userId}/role-mappings/clients/753b9b9b-5106-474d-b11f-cc4f8ba03fcd/")
   @Headers("Content-Type: application/x-www-form-urlencoded")
   ResponseEntity<String> getUserRoles(@PathVariable("userId") String userId, @RequestHeader HttpHeaders headers);

   @PostMapping(value = "/admin/realms/test/users/{userId}/role-mappings/clients/753b9b9b-5106-474d-b11f-cc4f8ba03fcd/")
   ResponseEntity<String> postUserRoles(@PathVariable("userId") String userId, @RequestHeader HttpHeaders headers,
         @RequestBody List<RoleDTO> formData);

   @GetMapping(value = "/admin/realms/test/clients/753b9b9b-5106-474d-b11f-cc4f8ba03fcd/roles/{roleName}/users")
   ResponseEntity<String> getUsersByRole(@PathVariable("roleName") String roleName, @RequestHeader HttpHeaders headers);

   @PostMapping(value = "/admin/realms/test/users")
   ResponseEntity<String> createUser(@RequestHeader HttpHeaders headers, @RequestBody Object dto);
}


// http://localhost:8181/admin/realms/test/users