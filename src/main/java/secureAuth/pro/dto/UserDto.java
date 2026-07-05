package secureAuth.pro.dto;

import secureAuth.pro.domain.Role;
import secureAuth.pro.domain.User;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public record UserDto (
        UUID id,
        String email,
        String displayName,
        UUID tenantId,
        boolean enabled,
        boolean mfaEnabled,
        Set<String> roles,
        Instant createdAt
){
    public static UserDto from(User user) {
        Set<String> roleNames = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());
        return new UserDto(
                user.getId(),
                user.getEmail(),
                user.getDisplayName(),
                user.getTenantId(),
                user.isEnabled(),
                user.isMfaEnabled(),
                roleNames,
                user.getCreatedAt()
        );
    }
}
