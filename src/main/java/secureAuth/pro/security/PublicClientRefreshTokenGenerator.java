package secureAuth.pro.security;

import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import org.jspecify.annotations.Nullable;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
/**
 * Issues refresh tokens to PUBLIC clients, which Spring Authorization Server
 * declines to do by default.
 *
 * <p>The framework's {@code OAuth2RefreshTokenGenerator} returns {@code null} for the
 * authorization_code grant when the client authenticated with
 * {@code ClientAuthenticationMethod.NONE} (see its private
 * {@code isPublicClientForAuthorizationCodeGrant}). That default is conservative: it
 * cannot know whether the deployment has the mitigations a refresh token in a browser
 * requires.
 *
 * <p>This deployment has them. The OAuth 2.0 for Browser-Based Apps BCP permits refresh
 * tokens for public clients provided they are one-time-use, rotated on every refresh, and
 * that detected reuse revokes the entire token family. SecureAuth implements all three:
 * rotation is forced by {@code TokenSettings.reuseRefreshTokens(false)} in
 * {@link JpaRegisteredClientRepository#toRegisteredClient}; family lineage is recorded by
 * {@link TrackingOAuth2AuthorizationService#recordLineage}; and reuse is detected in
 * {@link TrackingOAuth2AuthorizationService#findByToken}, which revokes the whole family
 * and writes a tenant-scoped {@code TOKEN_REUSE_DETECTED} audit row.
 *
 * <p>This class is otherwise an exact copy of the framework generator. Do NOT restore the
 * public-client check without first removing the rotation guarantees above — the two are
 * a package.
 */
public final class PublicClientRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {
    private final StringKeyGenerator refreshTokenGenerator =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
    private Clock clock = Clock.systemUTC();

    @Override
    public @Nullable OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
            return null;
        }
        Instant issuedAt = this.clock.instant();
        Instant expiresAt = issuedAt.plus(
                context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
        return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt);
    }

    public void setClock(Clock clock) {
        Assert.notNull(clock, "clock cannot be null");
        this.clock = clock;
    }
}
