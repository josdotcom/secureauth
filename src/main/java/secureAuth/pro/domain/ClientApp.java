package secureAuth.pro.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "client_apps")
@Setter
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ClientApp {

    private static final String AUTH_METHOD_SECRET_BASIC = "client_secret_basic";
    private static final String AUTH_METHOD_NONE = "none";

    /** Server-side app that can keep a secret: authenticates with client_secret_basic. */
    public static ClientApp confidential(UUID clientId, String clientSecretHash, String name,
                                         List<String> redirectUris, List<String> scopes,
                                         List<String> grantTypes, boolean requirePkce, UUID tenantId) {
        return new ClientApp(clientId, clientSecretHash, AUTH_METHOD_SECRET_BASIC, name,
                redirectUris, scopes, grantTypes, requirePkce, tenantId);
    }

    /** Browser SPA / native app: no secret is possible, so PKCE is mandatory. */
    public static ClientApp publicClient(UUID clientId, String name, List<String> redirectUris,
                                         List<String> scopes, List<String> grantTypes, UUID tenantId) {
        return new ClientApp(clientId, null, AUTH_METHOD_NONE, name, redirectUris,
                scopes, grantTypes, true, tenantId);
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Setter(AccessLevel.NONE)
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "client_id", nullable = false, unique = true)
    private UUID clientId;

    @Column(name = "client_secret_hash")
    private String clientSecretHash;

    @Column(name = "client_auth_method", nullable = false, length = 50)
    private String clientAuthMethod;

    @Column(length = 255)
    private String name;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "client_app_redirect_uris", joinColumns = @JoinColumn(name = "client_app_id"))
    @Column(name = "redirect_uri", nullable = false)
    private List<String> redirectUris;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "client_app_scopes", joinColumns = @JoinColumn(name = "client_app_id"))
    @Column(name = "scope", nullable = false)
    private List<String> scopes;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "client_app_grant_types", joinColumns = @JoinColumn(name = "client_app_id"))
    @Column(name = "grant_type", nullable = false)
    private List<String> grantTypes;

    @Column(name = "require_pkce", nullable = false)
    private boolean requirePkce;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @CreationTimestamp
    @Setter(AccessLevel.NONE)
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Setter(AccessLevel.NONE)
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    private ClientApp(UUID clientId, String clientSecretHash, String clientAuthMethod, String name, List<String> redirectUris, List<String> scopes, List<String> grantTypes, boolean requirePkce, UUID tenantId) {
        this.clientId = clientId;
        this.clientSecretHash = clientSecretHash;
        this.clientAuthMethod = clientAuthMethod;
        this.name = name;
        this.redirectUris = redirectUris;
        this.scopes = scopes;
        this.grantTypes = grantTypes;
        this.requirePkce = requirePkce;
        this.tenantId = tenantId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ClientApp clientApp)) return false;
        return clientId != null && clientId.equals(clientApp.clientId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId);
    }

    @Override
    public String toString() {
        return "ClientApp{" +
                "id=" + id +
                ", clientId=" + clientId +
                ", name='" + name + '\'' +
                ", tenantId=" + tenantId +
                '}';
    }
}
