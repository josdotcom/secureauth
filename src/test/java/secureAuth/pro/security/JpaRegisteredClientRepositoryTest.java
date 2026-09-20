package secureAuth.pro.security;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.util.ReflectionTestUtils;
import secureAuth.pro.domain.ClientApp;
import secureAuth.pro.repository.ClientAppRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JpaRegisteredClientRepositoryTest {

    private static final UUID CLIENT_ID = UUID.fromString("33333333-3333-3333-3333-333333333333");
    private static final UUID TENANT_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");

    private final ClientAppRepository clientApps = mock(ClientAppRepository.class);
    private final JpaRegisteredClientRepository repository = new JpaRegisteredClientRepository(clientApps);

    private static ClientApp withId(ClientApp app) {
        // id is @GeneratedValue with no setter, and toRegisteredClient dereferences it.
        ReflectionTestUtils.setField(app, "id", UUID.randomUUID());
        return app;
    }

    private static ClientApp publicApp() {
        return withId(ClientApp.publicClient(CLIENT_ID, "SecureAuth Demo SPA",
                List.of("http://127.0.0.1:5173/callback"), List.of("profile"),
                List.of("authorization_code", "refresh_token"), TENANT_ID));
    }

    private static ClientApp confidentialApp() {
        return withId(ClientApp.confidential(CLIENT_ID, "$2a$10$abcdefghijklmnopqrstuv", "Dev Client",
                List.of("http://127.0.0.1:8085/login/oauth2/code/dev"), List.of("profile"),
                List.of("authorization_code", "refresh_token"), true, TENANT_ID));
    }

    @Test
    void mapsPublicClientWithNoSecret() {
        when(clientApps.findByClientId(CLIENT_ID)).thenReturn(Optional.of(publicApp()));

        RegisteredClient client = repository.findByClientId(CLIENT_ID.toString());

        assertThat(client).isNotNull();
        assertThat(client.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(client.getClientSecret()).isNull();               // the .clientSecret() guard
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getAuthorizationGrantTypes()).containsExactlyInAnyOrder(
                AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN);
        assertThat(client.getTokenSettings().isReuseRefreshTokens()).isFalse();   // rotation is on
    }

    @Test
    void mapsConfidentialClientWithSecret() {
        when(clientApps.findByClientId(CLIENT_ID)).thenReturn(Optional.of(confidentialApp()));

        RegisteredClient client = repository.findByClientId(CLIENT_ID.toString());

        assertThat(client.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(client.getClientSecret()).isNotNull();
    }

    @Test
    void failsLoudOnUnknownAuthenticationMethod() {
        ClientApp app = publicApp();
        app.setClientAuthMethod("carrier_pigeon");
        when(clientApps.findByClientId(CLIENT_ID)).thenReturn(Optional.of(app));

        assertThatThrownBy(() -> repository.findByClientId(CLIENT_ID.toString()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("carrier_pigeon");
    }

    @Test
    void failsLoudOnUnknownGrantType() {
        ClientApp app = publicApp();
        app.setGrantTypes(List.of("password"));
        when(clientApps.findByClientId(CLIENT_ID)).thenReturn(Optional.of(app));

        assertThatThrownBy(() -> repository.findByClientId(CLIENT_ID.toString()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("password");
    }

    @Test
    void returnsNullForMalformedClientId() {
        assertThat(repository.findByClientId("not-a-uuid")).isNull();
    }

    @Test
    void returnsNullWhenClientDoesNotExist() {
        when(clientApps.findByClientId(CLIENT_ID)).thenReturn(Optional.empty());

        assertThat(repository.findByClientId(CLIENT_ID.toString())).isNull();
    }
}