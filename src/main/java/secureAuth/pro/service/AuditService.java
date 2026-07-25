package secureAuth.pro.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import secureAuth.pro.domain.AuditLog;
import secureAuth.pro.domain.enums.AuditAction;
import secureAuth.pro.repository.AuditLogRepository;

import java.util.UUID;

@Service
public class AuditService {
    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(AuditAction auditAction, UUID tenantId, UUID actorUserId, String target, String ipAddress) {
        AuditLog log = new AuditLog(null, actorUserId, auditAction, target, ipAddress, tenantId);
        auditLogRepository.save(log);
    }
}
