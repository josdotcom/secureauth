package secureAuth.pro.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import secureAuth.pro.domain.enums.AuditAction;
import secureAuth.pro.security.MfaAuthenticationSuccessHandler;
import secureAuth.pro.security.RequestUtils;
import secureAuth.pro.security.UserPrincipal;
import secureAuth.pro.security.UserPrincipalService;
import secureAuth.pro.service.AuditService;
import secureAuth.pro.service.MfaService;

import java.io.IOException;
import java.util.UUID;

@Controller
public class MfaChallengeController {
    private final MfaService mfaService;
    private final UserPrincipalService userPrincipalService;
    private final AuditService auditService;

    public MfaChallengeController(MfaService mfaService, UserPrincipalService userPrincipalService, AuditService auditService) {
        this.mfaService = mfaService;
        this.userPrincipalService = userPrincipalService;
        this.auditService = auditService;
    }

    @GetMapping("/mfa")
    public String mfaPage(@RequestParam(required = false) String error, Model model) {
        if (error != null) {
            model.addAttribute("error", "Invalid code - please try again.");
        }
        return "mfa";
    }

    @PostMapping("/mfa")
    public void verify(@RequestParam String code,
                       HttpServletRequest request,
                       HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession(false);
        UUID pendingUid = (session == null) ? null
                : (UUID) session.getAttribute(MfaAuthenticationSuccessHandler.MFA_PENDING_UID);

        if (pendingUid == null) {
            response.sendRedirect(request.getContextPath() + "/login");
            return;
        }

        if (!mfaService.verifyLoginCode(pendingUid, code)) {
            response.sendRedirect(request.getContextPath() + "/mfa?error");
            return;
        }

        UserPrincipal principal = userPrincipalService.loadByUserId(pendingUid);
        Authentication authentication = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
        session.removeAttribute(MfaAuthenticationSuccessHandler.MFA_PENDING_UID);

        auditService.record(AuditAction.LOGIN_SUCCESS, principal.getTenantId(), principal.getUserId(), principal.getUsername(), RequestUtils.clientIp(request));
        SavedRequest saved = new HttpSessionRequestCache().getRequest(request, response);
        response.sendRedirect(saved != null ? saved.getRedirectUrl() : request.getContextPath() + "/");
    }
}
