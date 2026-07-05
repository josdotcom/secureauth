package secureAuth.pro.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import secureAuth.pro.domain.User;
import secureAuth.pro.dto.UserDto;
import secureAuth.pro.exception.EmailAlreadyExistsException;
import secureAuth.pro.exception.InvalidCredentialsException;
import secureAuth.pro.repository.UserRepository;

import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public UserDto register(UUID tenantId, String email, String rawPassword, String displayName) {
        if (userRepository.existsByTenantIdAndEmail(tenantId, email)) {
            throw new EmailAlreadyExistsException(email);
        }
        User user = new User(email, passwordEncoder.encode(rawPassword), tenantId);
        user.setDisplayName(displayName);
        User saved = userRepository.save(user);
        return UserDto.from(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public UserDto authenticate(UUID tenantId, String email, String rawPassword) {
        User user = userRepository.findByTenantIdAndEmail(tenantId, email)
                .orElseThrow(InvalidCredentialsException::new);
        if (!user.isEnabled() || user.isLocked()) {
            throw new InvalidCredentialsException();
        }
        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }
        return UserDto.from(user);
    }
}
