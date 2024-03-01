package com.diegojacober.app_auth_keycloak.domain.entities;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Data;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
public class KeycloakUserDetails implements UserDetails {
    
    private String username;
    private String password;
    private String token;
    private Collection<? extends GrantedAuthority> authorities;

    public KeycloakUserDetails(String username, String password, List<String> roles) {
        this.username = username;
        this.password = password;
        this.authorities = roles.stream()
                                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                                .collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    // Outros métodos UserDetails
    // Por exemplo: isEnabled(), isAccountNonExpired(), isAccountNonLocked(), isCredentialsNonExpired()

    @Override
    public boolean isEnabled() {
        return true; // Pode implementar lógica de ativação do usuário aqui, se necessário
    }

    @Override
    public boolean isAccountNonExpired() {
       return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;

    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
}
