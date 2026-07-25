package secureAuth.pro.config;

import jakarta.transaction.Transactional;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import secureAuth.pro.domain.Permission;
import secureAuth.pro.domain.Role;
import secureAuth.pro.domain.User;
import secureAuth.pro.repository.PermissionRepository;
import secureAuth.pro.repository.RoleRepository;
import secureAuth.pro.repository.UserRepository;
import secureAuth.pro.service.UserService;

import java.util.UUID;

@Component
@Profile("dev")
public class DevUserSeeder implements CommandLineRunner {
    private static final UUID DEV_TENANT_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final String DEV_EMAIL = "dev@secureauth.pro";
    private static final String ADMIN_ROLE = "ADMIN";

    private final UserService userService;
    private final UserRepository userRepository;
    private final PermissionRepository permissionRepository;
    private final RoleRepository roleRepository;

    public DevUserSeeder(UserService userService, UserRepository userRepository, PermissionRepository permissionRepository, RoleRepository roleRepository) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.permissionRepository = permissionRepository;
        this.roleRepository = roleRepository;
    }

    @Transactional
    @Override
    public void run(String... args) {
        if (!userRepository.existsByTenantIdAndEmail(DEV_TENANT_ID, DEV_EMAIL)) {
            userService.register(DEV_TENANT_ID, DEV_EMAIL, "dev-passwword", "Dev User");
        }

        Permission readUsers = permissionRepository.findByName("user:read")
                .orElseGet(() -> permissionRepository.save(new Permission("user:read", "Read Users")));
        Permission writeUsers = permissionRepository.findByName("user:write")
                .orElseGet(() -> permissionRepository.save(new Permission("user:write", "Write Users")));

        Role admin = roleRepository.findByTenantIdAndName(DEV_TENANT_ID, ADMIN_ROLE)
                .orElseGet(() -> roleRepository.save(new Role(ADMIN_ROLE, DEV_TENANT_ID)));
        admin.getPermissions().add(readUsers);
        admin.getPermissions().add(writeUsers);
        roleRepository.save(admin);

        User devUser = userRepository.findByTenantIdAndEmail(DEV_TENANT_ID, DEV_EMAIL)
                .orElseThrow(() -> new IllegalStateException("Dev user missing right after seeding"));
        if(!devUser.getRoles().contains(admin)) {
            devUser.addRole(admin);
            userRepository.save(devUser);
        }
    }
}
