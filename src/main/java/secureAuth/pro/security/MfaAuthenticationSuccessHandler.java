package secureAuth.pro.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Component;
import secureAuth.pro.domain.enums.AuditAction;
import secureAuth.pro.service.AuditService;
import secureAuth.pro.service.MfaService;

import java.io.IOException;

@Component
public class MfaAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    public static final String MFA_PENDING_UID = "MFA_PENDING_UID";

    private final MfaService mfaService;
    private final AuditService auditService;

    public MfaAuthenticationSuccessHandler(MfaService mfaService, AuditService auditService) {
        this.mfaService = mfaService;
        this.auditService = auditService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        if (!(authentication.getPrincipal() instanceof UserPrincipal user)) {
            super.onAuthenticationSuccess(request, response, authentication);
            return;
        }

        AuthResult authResult = mfaService.isMfaEnabled(user.getUserId())
                ? new AuthResult.MfaRequired(user.getUserId())
                : new AuthResult.Success(user.getUserId());

        switch (authResult) {
            case AuthResult.MfaRequired m -> {
                HttpSession session = request.getSession();
                session.setAttribute(MFA_PENDING_UID, m.userId());
                SecurityContextHolder.clearContext();
                session.removeAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
                response.sendRedirect(request.getContextPath() + "/mfa");
            }
            case AuthResult.Success success -> {
                auditService.record(AuditAction.LOGIN_SUCCESS, user.getTenantId(), user.getUserId(), user.getUsername(), RequestUtils.clientIp(request));
                super.onAuthenticationSuccess(request, response, authentication);
            }
            case AuthResult.Failure f ->
                throw new IllegalStateException("Unexpected failure after successful authentication");
        }
    }
}
