package secureAuth.pro.security;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import secureAuth.pro.domain.AuditLog;
import secureAuth.pro.domain.RefreshToken;
import secureAuth.pro.domain.enums.AuditAction;
import secureAuth.pro.domain.enums.TokenStatus;
import secureAuth.pro.repository.AuditLogRepository;
import secureAuth.pro.repository.RefreshTokenRepository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static secureAuth.pro.security.TokenHasher.sha256Hex;

public class TrackingOAuth2AuthorizationService implements OAuth2AuthorizationService {
    private final OAuth2AuthorizationService delegate;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final AuditLogRepository auditLogRepository;
    private static final Logger log = LoggerFactory.getLogger(TrackingOAuth2AuthorizationService.class);

    public TrackingOAuth2AuthorizationService(OAuth2AuthorizationService delegate, RefreshTokenRepository refreshTokenRepository, RegisteredClientRepository registeredClientRepository, AuditLogRepository auditLogRepository) {
        this.delegate = delegate;
        this.refreshTokenRepository = refreshTokenRepository;
        this.registeredClientRepository = registeredClientRepository;
        this.auditLogRepository = auditLogRepository;
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
        var result = delegate.findByToken(token, tokenType);
        if (result != null) return result;
        if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            var hash = sha256Hex(token);
            var tracked = refreshTokenRepository.findByTokenHash(hash);
            if (tracked.isPresent()) {
                RefreshToken retired = tracked.get();
                if (retired.getStatus()== TokenStatus.ROTATED || retired.getStatus() == TokenStatus.REVOKED) {
                    refreshTokenRepository.revokeFamily(retired.getFamilyId());
                    OAuth2Authorization active = delegate.findById(retired.getFamilyId().toString());
                    if (active != null) {
                        delegate.remove(active);
                        Authentication auth = active.getAttribute(java.security.Principal.class.getName());
                        UUID tenantId = (auth != null && auth.getPrincipal() instanceof UserPrincipal up) ? up.getTenantId() : null;
                        AuditLog auditLog = new AuditLog(null, retired.getUserId(), AuditAction.TOKEN_REUSE_DETECTED, "refresh_token_family:" + retired.getFamilyId(), clientIp(), tenantId);
                        auditLogRepository.save(auditLog);
                    }
                    log.warn("Refresh-token reuse detected - revoking family {} for user {}", retired.getFamilyId(), retired.getUserId());
                }
            }
        }
        return null;
    }

    private String clientIp() {
        var attrs = RequestContextHolder.getRequestAttributes();
        if (!(attrs instanceof ServletRequestAttributes servletRequestAttributes)) return null;
        HttpServletRequest servletRequest = servletRequestAttributes.getRequest();
        String forwarded = servletRequest.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return servletRequest.getRemoteAddr();
    }
    private void recordLineage(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2RefreshToken> rt = authorization.getRefreshToken();
        if (rt == null) return;

        String tokenValue = rt.getToken().getTokenValue();
        Instant expiresAt = rt.getToken().getExpiresAt();

        String hash = sha256Hex(tokenValue);
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
