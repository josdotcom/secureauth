package secureAuth.pro.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import secureAuth.pro.domain.Permission;
import secureAuth.pro.domain.Role;
import secureAuth.pro.domain.User;
import secureAuth.pro.repository.UserRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;


@Service
public class UserPrincipalService {
    private final UserRepository userRepository;

    UserPrincipalService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    @Transactional(readOnly = true)
    UserPrincipal loadByTenantAndEmail(UUID tenantId, String email) {
        User user = userRepository.findByTenantIdAndEmail(tenantId, email)
                .orElseThrow(() -> new UsernameNotFoundException("Invalid Credentials"));

        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (Role role : user.getRoles()) {
            grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
            for (Permission permission : role.getPermissions()) {
                grantedAuthorities.add(new SimpleGrantedAuthority(permission.getName()));
            }
        }

        return new UserPrincipal(
                user.getId(), user.getEmail(), user.getPasswordHash(), user.getTenantId(), user.isEnabled(), user.isLocked(), grantedAuthorities
        );
    }
}
