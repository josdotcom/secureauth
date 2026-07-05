package secureAuth.pro.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import secureAuth.pro.domain.enums.TokenStatus;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
@Setter
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Setter(AccessLevel.NONE)
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name="token_hash", nullable = false, unique = true, length = 255)
    private String tokenHash;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "client_id", nullable = false)
    private UUID clientId;

    @Column(name = "family_id", nullable = false)
    private UUID familyId;

    @Column(name = "parent_id")
    private UUID parentId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private TokenStatus status;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @CreationTimestamp
    @Setter(AccessLevel.NONE)
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public RefreshToken(String tokenHash, UUID userId, UUID clientId, UUID familyId, UUID parentId, Instant expiresAt) {
        this.tokenHash = tokenHash;
        this.userId = userId;
        this.clientId = clientId;
        this.familyId = familyId;
        this.parentId = parentId;
        this.status = TokenStatus.ACTIVE;
        this.expiresAt = expiresAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RefreshToken refreshToken)) return false;
        return tokenHash != null && tokenHash.equals(refreshToken.tokenHash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tokenHash);
    }

    @Override
    public String toString() {
        return "RefreshToken{" +
                "id=" + id +
                ", userId=" + userId +
                ", familyId=" + familyId +
                ", parentId=" + parentId +
                ", status=" + status +
                ", expiresAt=" + expiresAt +
                '}';
    }
}
