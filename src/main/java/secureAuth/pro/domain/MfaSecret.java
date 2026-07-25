package secureAuth.pro.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "mfa_secrets")
@Setter
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MfaSecret {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Setter(AccessLevel.NONE)
    @Column(updatable = false, nullable = false)
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY)
    @Setter(AccessLevel.NONE)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    @Column(name = "encrypted_secret", nullable = false, length = 255)
    private String encryptedSecret;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "mfa_recovery_codes", joinColumns = @JoinColumn(name = "mfa_secret_id"))
    @Column(name = "recovery_code", nullable = false, length = 255)
    private List<String> recoveryCodes = new ArrayList<>();

    @Column(nullable = false)
    private boolean confirmed;

    @CreationTimestamp
    @Setter(AccessLevel.NONE)
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public void confirm(List<String> recoveryCodeHashes) {
        this.confirmed = true;
        this.recoveryCodes = new ArrayList<>(recoveryCodeHashes);
    }

    public MfaSecret(User user, String encryptedSecret, List<String> recoveryCodes) {
        this.user = user;
        this.encryptedSecret = encryptedSecret;
        this.recoveryCodes = recoveryCodes;
        this.confirmed = false;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof MfaSecret that)) return false;
        return encryptedSecret != null && encryptedSecret.equals(that.encryptedSecret);
    }

    @Override
    public int hashCode() {
        return Objects.hash(encryptedSecret);
    }

    @Override
    public String toString() {
        return "MfaSecret{" +
                "id=" + id +
                ", userId=" + (user != null ? user.getId() : null) +
                ", confirmed=" + confirmed +
                '}';
    }
}
