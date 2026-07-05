package secureAuth.pro.service;

import secureAuth.pro.dto.UserDto;

import java.util.UUID;

public interface UserService {
    UserDto register(UUID tenantId, String email, String rawPassword, String displayName);
    UserDto authenticate(UUID tenantId, String email, String rawPassword);
}
