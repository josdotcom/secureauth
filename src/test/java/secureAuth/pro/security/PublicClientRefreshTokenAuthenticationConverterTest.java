package secureAuth.pro.security;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PublicClientRefreshTokenAuthenticationConverterTest {

    private static final String CLIENT_ID = "33333333-3333-3333-3333-333333333333";

    private final PublicClientRefreshTokenAuthenticationConverter converter =
            new PublicClientRefreshTokenAuthenticationConverter();

    private MockHttpServletRequest refreshRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.addParameter("grant_type", "refresh_token");
        request.addParameter("refresh_token", "a-refresh-token");
        request.addParameter("client_id", CLIENT_ID);
        return request;
    }

    @Test
    void identifiesPublicClientOnRefreshGrant() {
        Authentication authentication = converter.convert(refreshRequest());

        assertThat(authentication).isInstanceOf(OAuth2ClientAuthenticationToken.class);
        OAuth2ClientAuthenticationToken token = (OAuth2ClientAuthenticationToken) authentication;

        assertThat(token.getPrincipal()).isEqualTo(CLIENT_ID);
        assertThat(token.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
        assertThat(token.getCredentials()).isNull();
        assertThat(token.isAuthenticated()).isFalse();

        Map<String, Object> additional = token.getAdditionalParameters();
        assertThat(additional).containsEntry("grant_type", "refresh_token");
        assertThat(additional).doesNotContainKey("client_id");   // principal, not a parameter
    }

    /**
     * SECURITY - the most important assertion in this suite.
     *
     * <p>If this converter ever matches authorization_code, the client is identified with no
     * code_verifier, CodeVerifierAuthenticator never runs, and PKCE - the only protection a
     * public client has on the code exchange - is bypassed. An intercepted authorization code
     * would then be enough to mint tokens.
     */
    @Test
    void ignoresAuthorizationCodeGrantSoPkceIsNeverBypassed() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.addParameter("grant_type", "authorization_code");
        request.addParameter("code", "an-authorization-code");
        request.addParameter("client_id", CLIENT_ID);

        assertThat(converter.convert(request)).isNull();
    }

    @Test
    void ignoresRequestWithAuthorizationHeader() {
        MockHttpServletRequest request = refreshRequest();
        request.addHeader("Authorization", "Basic MTExMTpkZXYtc2VjcmV0");

        assertThat(converter.convert(request)).isNull();   // client_secret_basic owns this
    }

    @Test
    void ignoresRequestWithClientSecret() {
        MockHttpServletRequest request = refreshRequest();
        request.addParameter("client_secret", "dev-secret");

        assertThat(converter.convert(request)).isNull();   // client_secret_post owns this
    }

    @Test
    void ignoresRequestWithClientAssertion() {
        MockHttpServletRequest request = refreshRequest();
        request.addParameter("client_assertion", "eyJhbGciOiJSUzI1NiJ9.e30.sig");

        assertThat(converter.convert(request)).isNull();   // private_key_jwt owns this
    }

    @Test
    void rejectsMissingClientId() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.addParameter("grant_type", "refresh_token");
        request.addParameter("refresh_token", "a-refresh-token");

        assertThatThrownBy(() -> converter.convert(request))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void rejectsBlankClientId() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.addParameter("grant_type", "refresh_token");
        request.addParameter("client_id", "   ");

        assertThatThrownBy(() -> converter.convert(request))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    /** Duplicate client_id is a classic request-smuggling shape; SAS's own converters reject it. */
    @Test
    void rejectsDuplicateClientId() {
        MockHttpServletRequest request = refreshRequest();
        request.addParameter("client_id", "11111111-1111-1111-1111-111111111111");

        assertThatThrownBy(() -> converter.convert(request))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }
}