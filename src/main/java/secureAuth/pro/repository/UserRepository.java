package secureAuth.pro.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import secureAuth.pro.domain.User;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByTenantIdAndEmail(UUID tenantId, String email);
    boolean existsByTenantIdAndEmail(UUID tenantId, String email);
}
