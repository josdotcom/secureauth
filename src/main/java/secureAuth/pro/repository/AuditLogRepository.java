package secureAuth.pro.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import secureAuth.pro.domain.AuditLog;

import java.util.UUID;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {
    Page<AuditLog> findByTenantIdOrderByCreatedAtDesc(UUID tenantId, Pageable pageable);
    Page<AuditLog> findByActorUserIdOrderByCreatedAtDesc(UUID userId, Pageable pageable);
}
