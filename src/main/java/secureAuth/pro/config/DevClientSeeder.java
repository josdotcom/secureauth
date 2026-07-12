package secureAuth.pro.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import secureAuth.pro.domain.ClientApp;
import secureAuth.pro.repository.ClientAppRepository;

import java.util.List;
import java.util.UUID;

@Component
@Profile("dev")
public class DevClientSeeder implements CommandLineRunner {
    private static final UUID DEV_CLIENT_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID DEV_TENANT_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");

    private final ClientAppRepository clientAppRepository;
    private final PasswordEncoder passwordEncoder;

    public DevClientSeeder(ClientAppRepository clientAppRepository, PasswordEncoder passwordEncoder) {
        this.clientAppRepository = clientAppRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        if (clientAppRepository.findByClientId(DEV_CLIENT_ID).isPresent()) {
            return;
        }

        String secretHash = passwordEncoder.encode("dev-secret");

        ClientApp clientApp = new ClientApp(
                DEV_CLIENT_ID,
                secretHash,
                "Dev Test Client",
                List.of("http://127.0.0.1:8085/login/oauth2/code/dev"),
                List.of("openid", "profile", "email"),
                List.of("authorization_code", "refresh_token"),
                true,
                DEV_TENANT_ID
        );

        clientAppRepository.save(clientApp);
    }
}
