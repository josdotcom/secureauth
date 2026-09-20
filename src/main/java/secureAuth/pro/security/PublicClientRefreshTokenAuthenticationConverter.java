package secureAuth.pro.security;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * Identifies a PUBLIC client on the refresh_token grant.
 *
 * <p>Spring Authorization Server's {@code PublicClientAuthenticationConverter} only matches a
 * PKCE token request (authorization_code + code_verifier), so a public client refreshing a token
 * is never identified at all: the security context stays anonymous, chain 1's
 * {@code anyRequest().authenticated()} denies, and the token endpoint answers with a 302 to the
 * login page. This converter fills that gap.
 *
 * <p>This is IDENTIFICATION, not authentication — a public client has no credential, which is
 * what RFC 6749 §3.2.1 expects. Security on this grant comes from elsewhere: the refresh token is
 * a 96-byte bearer secret; {@code OAuth2RefreshTokenAuthenticationProvider} verifies the stored
 * authorization's registeredClientId matches this client, so one client cannot redeem another's
 * token; and rotation + reuse detection + family revocation bound the damage if it leaks
 * (see {@link PublicClientRefreshTokenGenerator}).
 */
public final class PublicClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {

    @Override
    public @Nullable Authentication convert(HttpServletRequest request) {
        Map<String, String[]> parameters = request.getParameterMap();

        // SECURITY-CRITICAL: refresh_token only. If this ever matched authorization_code it would
        // identify the client with no code_verifier, so CodeVerifierAuthenticator would never run
        // and PKCE — the ONLY protection a public client has on the code exchange — would be
        // bypassed. Do not relax this, and do not rely on converter ordering to save us.
        if (!AuthorizationGrantType.REFRESH_TOKEN.getValue()
                .equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))) {
            return null;
        }

        // A credential is present -> a credential-based converter owns this request.
        if (request.getHeader(HttpHeaders.AUTHORIZATION) != null) {
            return null;                                              // client_secret_basic
        }
        if (parameters.containsKey(OAuth2ParameterNames.CLIENT_SECRET)) {
            return null;                                              // client_secret_post
        }
        if (parameters.containsKey(OAuth2ParameterNames.CLIENT_ASSERTION)) {
            return null;                                              // private_key_jwt
        }

        // Past this point the request IS ours, so malformed input is an error, not a pass-through.
        // Matches how PublicClientAuthenticationConverter distinguishes "not mine" from "broken".
        String[] clientIdParams = parameters.get(OAuth2ParameterNames.CLIENT_ID);
        if (clientIdParams == null || clientIdParams.length != 1 || !StringUtils.hasText(clientIdParams[0])) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        String clientId = clientIdParams[0];

        // NOTE: getParameterMap() merges query-string and form parameters, where SAS reads form
        // data only. Deliberate simplification: OAuth2EndpointUtils is package-private, and
        // client_id is a public identifier rather than a secret.
        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, values) -> {
            if (!OAuth2ParameterNames.CLIENT_ID.equals(key)) {
                additionalParameters.put(key, values.length == 1 ? values[0] : values);
            }
        });

        return new OAuth2ClientAuthenticationToken(
                clientId, ClientAuthenticationMethod.NONE, null, additionalParameters);
    }
}