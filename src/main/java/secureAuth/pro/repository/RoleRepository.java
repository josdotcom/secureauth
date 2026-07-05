package secureAuth.pro.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import secureAuth.pro.domain.Role;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {
    Optional<Role> findByTenantIdAndName(UUID tenantId, String name);
    List<Role> findByTenantId(UUID tenantId);
}
