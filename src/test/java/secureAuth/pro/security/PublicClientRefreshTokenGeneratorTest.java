package secureAuth.pro.security;

import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PublicClientRefreshTokenGeneratorTest {

    private final PublicClientRefreshTokenGenerator generator = new PublicClientRefreshTokenGenerator();

    private static RegisteredClient publicClient(Duration refreshTtl) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("33333333-3333-3333-3333-333333333333")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:5173/callback")
                .scope("profile")
                .tokenSettings(TokenSettings.builder()
                        .reuseRefreshTokens(false)
                        .refreshTokenTimeToLive(refreshTtl)
                        .build())
                .build();
    }

    private static OAuth2TokenContext context(OAuth2TokenType tokenType, RegisteredClient client) {
        OAuth2TokenContext context = mock(OAuth2TokenContext.class);
        when(context.getTokenType()).thenReturn(tokenType);
        when(context.getRegisteredClient()).thenReturn(client);
        return context;
    }

    /**
     * The whole point of this class: Spring Authorization Server's own generator returns null
     * here because the client authenticates with NONE. Ours issues, because rotation and reuse
     * detection are in place (see the class javadoc).
     */
    @Test
    void issuesRefreshTokenToPublicClient() {
        OAuth2RefreshToken token =
                generator.generate(context(OAuth2TokenType.REFRESH_TOKEN, publicClient(Duration.ofDays(7))));

        assertThat(token).isNotNull();
        assertThat(token.getTokenValue()).hasSize(128);   // 96 bytes, Base64URL, unpadded
    }

    @Test
    void honoursTheClientsConfiguredTimeToLive() {
        OAuth2RefreshToken token =
                generator.generate(context(OAuth2TokenType.REFRESH_TOKEN, publicClient(Duration.ofHours(6))));

        assertThat(Duration.between(token.getIssuedAt(), token.getExpiresAt()))
                .isEqualTo(Duration.ofHours(6));
    }

    /** "Not mine" - DelegatingOAuth2TokenGenerator asks every generator for every token type. */
    @Test
    void returnsNullForNonRefreshTokenTypes() {
        assertThat(generator.generate(
                context(OAuth2TokenType.ACCESS_TOKEN, publicClient(Duration.ofDays(7))))).isNull();
    }
}