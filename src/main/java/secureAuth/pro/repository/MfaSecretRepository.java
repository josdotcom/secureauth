package secureAuth.pro.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import secureAuth.pro.domain.MfaSecret;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface MfaSecretRepository extends JpaRepository<MfaSecret, UUID> {
    Optional<MfaSecret> findByUser_Id(UUID userId);
}
