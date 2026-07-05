package secureAuth.pro.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import secureAuth.pro.domain.enums.AuditAction;

import java.util.UUID;

@Entity
@Table(name = "audit_logs")
@Setter
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuditLog {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Setter(AccessLevel.NONE)
    @Column(updatable = false, nullable = false)
    private UUID id;

    @Column(name = "actor_user_id")
    private UUID actorUserId;

    @Enumerated(EnumType.STRING)
    @Column(name = "audit_log_action", nullable = false, length = 50)
    private AuditAction action;

    @Column(nullable = false, length = 255)
    private String target;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @CreationTimestamp
    @Setter(AccessLevel.NONE)
    @Column(name = "created_at", nullable = false, updatable = false)
    private java.time.Instant createdAt;

    public AuditLog(User user, UUID actorUserId, AuditAction action, String target, String ipAddress, UUID tenantId) {
        this.actorUserId = actorUserId;
        this.action = action;
        this.target = target;
        this.ipAddress = ipAddress;
        this.tenantId = tenantId;
    }

    @Override
    public String toString() {
        return "AuditLog{" +
                "id=" + id +
                ", actorUserId=" + actorUserId +
                ", action=" + action +
                ", target='" + target + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                ", tenantId=" + tenantId +
                ", createdAt=" + createdAt +
                '}';
    }
}
