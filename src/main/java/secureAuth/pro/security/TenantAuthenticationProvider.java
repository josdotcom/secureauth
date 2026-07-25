package secureAuth.pro.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import secureAuth.pro.domain.ClientApp;
import secureAuth.pro.domain.enums.AuditAction;
import secureAuth.pro.repository.ClientAppRepository;
import secureAuth.pro.service.AuditService;

import java.util.UUID;

@Component
public class TenantAuthenticationProvider implements AuthenticationProvider {
    private final UserPrincipalService userPrincipalService;
    private final ClientAppRepository clientAppRepository;
    private final PasswordEncoder passwordEncoder;
    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final AuditService auditService;

    public TenantAuthenticationProvider(UserPrincipalService userPrincipalService, ClientAppRepository clientAppRepository, PasswordEncoder passwordEncoder, AuditService auditService) {
        this.userPrincipalService = userPrincipalService;
        this.clientAppRepository = clientAppRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String email = authentication.getName();
        if (authentication.getCredentials() == null) {
            throw new BadCredentialsException("Invalid credentials");
        }
        String rawPassword = authentication.getCredentials().toString();

        UUID tenantId = resolveTenantId();

        try {
            UserPrincipal principal = userPrincipalService.loadByTenantAndEmail(tenantId, email);

            if (!passwordEncoder.matches(rawPassword, principal.getPassword())) {
                throw new BadCredentialsException("Invalid credentials");
            }
            if (!principal.isEnabled()) {
                throw new DisabledException("Account disabled");
            }
            if (!principal.isAccountNonLocked()) {
                throw new LockedException("Account locked");
            }

            return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
        } catch (AuthenticationException e) {
            auditService.record(AuditAction.LOGIN_FAILURE, tenantId, null, email, clientIp());
            throw e;
        }
    }

    private String clientIp() {
        var attrs = RequestContextHolder.getRequestAttributes();
        if (!(attrs instanceof ServletRequestAttributes servletAttrs)) return null;
        HttpServletRequest request = servletAttrs.getRequest();
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private UUID resolveTenantId() {
        ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = requestAttributes.getRequest();
        HttpServletResponse response = requestAttributes.getResponse();

        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest == null) {
            throw new BadCredentialsException("No authorization request in progress");
        }
        String[] clientIds = savedRequest.getParameterValues("client_id");
        if (clientIds == null || clientIds.length == 0) {
            throw new BadCredentialsException("Missing client_id");
        }

        UUID clientUuid = UUID.fromString(clientIds[0]);
        ClientApp clientApp = clientAppRepository.findByClientId(clientUuid)
                .orElseThrow(() -> new BadCredentialsException("Unknown Client"));
        return clientApp.getTenantId();
    }
}
