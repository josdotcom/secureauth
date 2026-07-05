package secureAuth.pro.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import secureAuth.pro.domain.RefreshToken;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByTokenHash(String refreshToken);
    List<RefreshToken> findByFamilyId(UUID tenantId);

    @Modifying
    @Query("update RefreshToken t set t.status = secureAuth.pro.domain.enums.TokenStatus.REVOKED " + "where t.familyId = :familyId")
    void revokeFamily(@Param("familyId") UUID familyId);

    int deleteByExpiresAtBefore(Instant cutoff);
}
