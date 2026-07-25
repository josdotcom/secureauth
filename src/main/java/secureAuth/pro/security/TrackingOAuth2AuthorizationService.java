package secureAuth.pro.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import secureAuth.pro.domain.RefreshToken;
import secureAuth.pro.domain.enums.TokenStatus;
import secureAuth.pro.repository.RefreshTokenRepository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public class TrackingOAuth2AuthorizationService implements OAuth2AuthorizationService {
    private final OAuth2AuthorizationService delegate;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RegisteredClientRepository registeredClientRepository;

    public TrackingOAuth2AuthorizationService(OAuth2AuthorizationService delegate, RefreshTokenRepository refreshTokenRepository, RegisteredClientRepository registeredClientRepository) {
        this.delegate = delegate;
        this.refreshTokenRepository = refreshTokenRepository;
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        delegate.save(authorization);
        recordLineage(authorization);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        return delegate.findByToken(token, tokenType);
    }

    private void recordLineage(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2RefreshToken> rt = authorization.getRefreshToken();
        if (rt == null) return;

        String tokenValue = rt.getToken().getTokenValue();
        Instant expiresAt = rt.getToken().getExpiresAt();

        String hash = TokenHasher.sha256Hex(tokenValue);
        if(refreshTokenRepository.findByTokenHash(hash).isPresent()) return;

        UUID familyId = UUID.fromString(authorization.getId());

        UUID parentId = null;
        Optional<RefreshToken> current = refreshTokenRepository.findByFamilyIdAndStatus(familyId, TokenStatus.ACTIVE);

        if (current.isPresent()) {
            RefreshToken previous = current.get();
            previous.setStatus(TokenStatus.ROTATED);
            refreshTokenRepository.save(previous);
            parentId = previous.getId();
        }

        Authentication auth = authorization.getAttribute(java.security.Principal.class.getName());
        UUID userId = (auth != null && auth.getPrincipal() instanceof UserPrincipal up) ? up.getUserId() : null;

        RegisteredClient rc = registeredClientRepository.findById(authorization.getRegisteredClientId());
        UUID clientId = UUID.fromString(rc.getClientId());

        refreshTokenRepository.save(new RefreshToken(hash, userId, clientId, familyId, parentId, expiresAt));
    }
}
