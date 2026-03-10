package dev.saseq.configs;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Open Dynamic Client Registration endpoint (RFC 7591) for MCP clients like Claude.ai.
 * Claude.ai POSTs to /register without a Bearer token, expecting the server to accept
 * the registration and return client_id + client_secret.
 */
@RestController
public class ClientRegistrationController {

    private final RegisteredClientRepository clientRepository;

    public ClientRegistrationController(RegisteredClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    @SuppressWarnings("unchecked")
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> registerClient(@RequestBody Map<String, Object> request) {
        String clientName = (String) request.getOrDefault("client_name", "mcp-client");
        List<String> redirectUris = (List<String>) request.getOrDefault("redirect_uris", List.of());
        List<String> grantTypes = (List<String>) request.getOrDefault("grant_types",
                List.of("authorization_code"));

        String clientId = "mcp-" + UUID.randomUUID().toString().substring(0, 8);
        String clientSecret = UUID.randomUUID().toString();

        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret("{noop}" + clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build());

        for (String grantType : grantTypes) {
            switch (grantType) {
                case "authorization_code" -> builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                case "refresh_token" -> builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
                case "client_credentials" -> builder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
            }
        }

        for (String uri : redirectUris) {
            builder.redirectUri(uri);
        }

        if (redirectUris.isEmpty()) {
            builder.redirectUri("https://claude.ai/api/mcp/auth_callback");
        }

        RegisteredClient registeredClient = builder.build();
        clientRepository.save(registeredClient);

        Map<String, Object> response = new HashMap<>();
        response.put("client_id", clientId);
        response.put("client_secret", clientSecret);
        response.put("client_name", clientName);
        response.put("grant_types", grantTypes);
        response.put("redirect_uris", redirectUris.isEmpty()
                ? List.of("https://claude.ai/api/mcp/auth_callback")
                : redirectUris);
        response.put("token_endpoint_auth_method", "client_secret_basic");
        response.put("response_types", List.of("code"));

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
