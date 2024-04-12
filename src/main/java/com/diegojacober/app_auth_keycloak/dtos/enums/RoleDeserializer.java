package com.diegojacober.app_auth_keycloak.dtos.enums;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

public class RoleDeserializer extends StdDeserializer<Role> {

    public RoleDeserializer() {
        this(null);
    }

    public RoleDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public Role deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
        JsonNode node = jp.getCodec().readTree(jp);
        String roleName = node.asText().toUpperCase(); // Convertendo para maiúsculas para evitar problemas de case
                                                       // sensitivity
        try {
            return Role.valueOf(roleName);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Role inválida: " + roleName);
        }
    }
}