package secureAuth.pro.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import secureAuth.pro.repository.UserRepository;
import secureAuth.pro.service.UserService;

import java.util.UUID;

@Component
@Profile("dev")
public class DevUserSeeder implements CommandLineRunner {
    private static final UUID DEV_TENANT_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final String DEV_EMAIL = "dev@secureauth.pro";
    private final UserService userService;
    private final UserRepository userRepository;

    public DevUserSeeder(UserService userService, UserRepository userRepository) {
        this.userService = userService;
        this.userRepository = userRepository;
    }

    @Override
    public void run(String... args) {
        if (userRepository.existsByTenantIdAndEmail(DEV_TENANT_ID, DEV_EMAIL)) {
            return;
        }
        userService.register(DEV_TENANT_ID, DEV_EMAIL, "dev-password", "Dev User");
    }
}
