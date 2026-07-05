package secureAuth.pro.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import secureAuth.pro.domain.ClientApp;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ClientAppRepository extends JpaRepository<ClientApp, UUID> {
    Optional<ClientApp> findByClientId(UUID clientId);
    List<ClientApp> findByTenantId(UUID tenantId);
}
