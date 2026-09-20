package secureAuth.pro.security;

import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PublicClientRefreshTokenAuthenticationProviderTest {

    private static final String CLIENT_ID = "33333333-3333-3333-3333-333333333333";

    private final RegisteredClientRepository clients = mock(RegisteredClientRepository.class);
    private final PublicClientRefreshTokenAuthenticationProvider provider =
            new PublicClientRefreshTokenAuthenticationProvider(clients);

    private static OAuth2ClientAuthenticationToken request(String grantType) {
        return new OAuth2ClientAuthenticationToken(
                CLIENT_ID, ClientAuthenticationMethod.NONE, null, Map.of("grant_type", grantType));
    }

    private static RegisteredClient.Builder client(ClientAuthenticationMethod method) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientAuthenticationMethod(method)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1:5173/callback")
                .scope("profile");
    }

    @Test
    void authenticatesRegisteredPublicClient() {
        RegisteredClient registered = client(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).build();
        when(clients.findByClientId(CLIENT_ID)).thenReturn(registered);

        Authentication result = provider.authenticate(request("refresh_token"));

        assertThat(result).isInstanceOf(OAuth2ClientAuthenticationToken.class);
        OAuth2ClientAuthenticationToken token = (OAuth2ClientAuthenticationToken) result;
        assertThat(token.isAuthenticated()).isTrue();
        assertThat(token.getRegisteredClient()).isSameAs(registered);
        assertThat(token.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
    }

    /** SECURITY - mirrors the converter guard. Both must refuse the code exchange. */
    @Test
    void ignoresAuthorizationCodeGrantSoPkceIsNeverBypassed() {
        assertThat(provider.authenticate(request("authorization_code"))).isNull();
    }

    @Test
    void ignoresTokensFromOtherAuthenticationMethods() {
        OAuth2ClientAuthenticationToken basic = new OAuth2ClientAuthenticationToken(
                CLIENT_ID, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "secret",
                Map.of("grant_type", "refresh_token"));

        assertThat(provider.authenticate(basic)).isNull();
    }

    @Test
    void rejectsUnknownClient() {
        when(clients.findByClientId(CLIENT_ID)).thenReturn(null);

        assertThatThrownBy(() -> provider.authenticate(request("refresh_token")))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(e -> assertThat(((OAuth2AuthenticationException) e).getError().getErrorCode())
                        .isEqualTo("invalid_client"));
    }

    /** A confidential client must not be able to shed its secret by simply omitting it. */
    @Test
    void rejectsConfidentialClient() {
        when(clients.findByClientId(CLIENT_ID)).thenReturn(
                client(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .clientSecret("{bcrypt}$2a$10$abcdefghijklmnopqrstuv")
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).build());

        assertThatThrownBy(() -> provider.authenticate(request("refresh_token")))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(e -> assertThat(((OAuth2AuthenticationException) e).getError().getErrorCode())
                        .isEqualTo("invalid_client"));
    }

    @Test
    void rejectsClientNotAuthorizedForRefreshGrant() {
        when(clients.findByClientId(CLIENT_ID))
                .thenReturn(client(ClientAuthenticationMethod.NONE).build());   // no refresh_token

        assertThatThrownBy(() -> provider.authenticate(request("refresh_token")))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(e -> assertThat(((OAuth2AuthenticationException) e).getError().getErrorCode())
                        .isEqualTo("unauthorized_client"));
    }
}