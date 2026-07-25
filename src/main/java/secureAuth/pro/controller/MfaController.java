package secureAuth.pro.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import secureAuth.pro.domain.enums.AuditAction;
import secureAuth.pro.security.RequestUtils;
import secureAuth.pro.service.AuditService;
import secureAuth.pro.service.MfaService;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/mfa")
public class MfaController {
    private final MfaService mfaService;
    private final AuditService auditService;

    public MfaController(MfaService mfaService, AuditService auditService) {
        this.mfaService = mfaService;
        this.auditService = auditService;
    }

    @PostMapping("/enroll")
    public MfaService.MfaEnrollmentResponse enroll(@AuthenticationPrincipal Jwt jwt) {
        UUID userId = UUID.fromString(jwt.getClaimAsString("uid"));
        return mfaService.beginEnrollment(userId);
    }

    @PostMapping("/confirm")
    public ConfirmResponse confirm(@AuthenticationPrincipal Jwt jwt, @RequestBody ConfirmRequest request, HttpServletRequest httpRequest) {
        UUID userId = UUID.fromString(jwt.getClaimAsString("uid"));
        List<String> recoveryCodes = mfaService.confirmEnrollment(userId, request.code());

        auditService.record(AuditAction.MFA_ENABLED, UUID.fromString(jwt.getClaimAsString("tenant")), userId, jwt.getSubject(), RequestUtils.clientIp(httpRequest));
        return  new ConfirmResponse(recoveryCodes);
    }

    public record ConfirmRequest(String code) {};
    public record ConfirmResponse(List<String> recoveryCodes) {};
}
