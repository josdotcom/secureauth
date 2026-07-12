package secureAuth.pro.security;

import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import secureAuth.pro.domain.ClientApp;
import secureAuth.pro.repository.ClientAppRepository;

import java.util.Optional;
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
        return RegisteredClient.withId(clientApp.getId().toString())
                .clientId(clientApp.getClientId().toString())
                .clientSecret("{bcrypt}" + clientApp.getClientSecretHash())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUris(uris -> uris.addAll(clientApp.getRedirectUris()))
                .scopes(scopes -> scopes.addAll(clientApp.getScopes()))
                .build();
    }
}
