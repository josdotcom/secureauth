package secureAuth.pro.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.time.Instant;

@Entity
@Table(
    name = "users",
    uniqueConstraints = {
            @UniqueConstraint(name = "uk_user_tenant_email", columnNames = {"tenant_id", "email"})
    }
)
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Setter(AccessLevel.NONE)
    @Column(updatable = false, nullable = false)
    private UUID id;

    @Column(nullable = false, length = 255)
    private String email;

    @Column(name="password_hash", nullable = false)
    private String passwordHash;

    @Column(name="display_name", length = 150)
    private String displayName;

    @Column(name = "mfa_enabled", nullable = false)
    private boolean mfaEnabled = false;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(nullable = false)
    private boolean locked = false;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Setter(AccessLevel.NONE)
    private Set<Role> roles = new HashSet<>();

    @CreationTimestamp
    @Setter(AccessLevel.NONE)
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Setter(AccessLevel.NONE)
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public User(String email, String passwordHash, UUID tenantId) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.tenantId = tenantId;
    }

    public void addRole(Role role) {
        this.roles.add(role);
    }

    public void removeRole(Role role) {
        this.roles.remove(role);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User other)) return false;
        return email != null && email.equals(other.email);
    }

    @Override
    public int hashCode() {
        return Objects.hash(email);
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", email='" + email + '\'' +
                ", tenantId=" + tenantId +
                '}';
    }

}
