package secureAuth.pro.security;

import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import secureAuth.pro.domain.ClientApp;
import secureAuth.pro.repository.ClientAppRepository;

import java.time.Duration;
import java.util.UUID;

@Repository
public class JpaRegisteredClientRepository implements RegisteredClientRepository {
    private final ClientAppRepository clientAppRepository;

    JpaRegisteredClientRepository(ClientAppRepository clientAppRepository) {
        this.clientAppRepository = clientAppRepository;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        throw new UnsupportedOperationException("Client registration is managed via the client_apps table.");
    }

    @Override
    @Transactional(readOnly = true)
    public @Nullable RegisteredClient findById(String id) {
        try {
            return clientAppRepository.findById(UUID.fromString(id))
                    .map(this::toRegisteredClient)
                    .orElse(null);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    @Transactional(readOnly = true)
    @Override
    public @Nullable RegisteredClient findByClientId(String clientId) {
        UUID clientUuid;
        try {
            clientUuid = UUID.fromString(clientId);
        } catch (IllegalArgumentException e) {
            return null;
        }
        return clientAppRepository.findByClientId(clientUuid)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    private RegisteredClient toRegisteredClient(ClientApp clientApp) {
        RegisteredClient.Builder builder = RegisteredClient.withId(clientApp.getId().toString())
                .clientId(clientApp.getClientId().toString())
                .clientAuthenticationMethod(mapAuthMethod(clientApp.getClientAuthMethod()))
                .authorizationGrantTypes(grantTypes ->
                        clientApp.getGrantTypes().forEach(grantType -> grantTypes.add(mapGrantType(grantType)))
                )
                .redirectUris(uris -> uris.addAll(clientApp.getRedirectUris()))
                .scopes(scopes -> scopes.addAll(clientApp.getScopes()))
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(clientApp.isRequirePkce())
                        .requireAuthorizationConsent(false)
                        .build()
                )
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .reuseRefreshTokens(false)
                        .build());
        if (clientApp.getClientSecretHash() != null) {
            builder.clientSecret(clientApp.getClientSecretHash());
        }

        return builder.build();
    }

    private static AuthorizationGrantType mapGrantType(String value) {
        return switch (value) {
            case "authorization_code" -> AuthorizationGrantType.AUTHORIZATION_CODE;
            case "refresh_token" -> AuthorizationGrantType.REFRESH_TOKEN;
            case "client_credentials" -> AuthorizationGrantType.CLIENT_CREDENTIALS;
            default -> throw new IllegalArgumentException("Invalid authorization grant type: " + value);
        };
    }

    private static ClientAuthenticationMethod mapAuthMethod(String authMethod) {
        return switch (authMethod) {
            case "client_secret_basic" -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
            case "client_secret_post" -> ClientAuthenticationMethod.CLIENT_SECRET_POST;
            case "none" -> ClientAuthenticationMethod.NONE;
            case "private_key_jwt" -> ClientAuthenticationMethod.PRIVATE_KEY_JWT;
            default -> throw new IllegalArgumentException("Unsupported client authentication method: " + authMethod);
        };
    }
}
