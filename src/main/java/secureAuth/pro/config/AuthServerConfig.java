package secureAuth.pro.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.jackson.SecurityJacksonModule;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import secureAuth.pro.repository.RefreshTokenRepository;
import secureAuth.pro.security.TenantAuthenticationProvider;
import secureAuth.pro.security.TrackingOAuth2AuthorizationService;
import secureAuth.pro.security.UserPrincipal;
import secureAuth.pro.security.UserPrincipalMixin;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Configuration
public class AuthServerConfig {

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean @Order(1)
    SecurityFilterChain authServer(HttpSecurity http) throws Exception {
        http.oauth2AuthorizationServer(authServer-> {
            http.securityMatcher(authServer.getEndpointsMatcher());
            authServer.oidc(Customizer.withDefaults());
        })
        .authorizeHttpRequests(a -> a.anyRequest().authenticated())
        .exceptionHandling(e -> e.defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
        ));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain appSecurity(HttpSecurity http, TenantAuthenticationProvider tenantAuthenticationProvider) throws Exception {
        http
                .authenticationProvider(tenantAuthenticationProvider)
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(a -> a
                .requestMatchers("/api/register", "/api/login","/login").permitAll()
                .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRSAKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                return;
            }
            if (!(context.getPrincipal().getPrincipal() instanceof UserPrincipal principal)) {
                return;
            }

            List<String> roles = new ArrayList<>();
            List<String> authorities = new ArrayList<>();
            for (GrantedAuthority authority: principal.getAuthorities()) {
                String value = authority.getAuthority();
                if (value.startsWith("ROLE_")) {
                    roles.add(value.substring("ROLE_".length()));
                } else {
                    authorities.add(value);
                }
            }

            context.getClaims()
                    .claim("tenant", principal.getTenantId().toString())
                    .claim("uid", principal.getUserId().toString())
                    .claim("roles", roles)
                    .claim("authorities", authorities);
        };
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcOperations jdbcOperations,
            RegisteredClientRepository registeredClientRepository,
            RefreshTokenRepository refreshTokenRepository
    ) {
        var service = new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
        var ptvBuilder = BasicPolymorphicTypeValidator.builder().allowIfSubType(UserPrincipal.class);
        var securityModules = SecurityJacksonModules.getModules(getClass().getClassLoader(), ptvBuilder);

        var jsonMapper = JsonMapper.builder()
                .addModules(securityModules)
                .addMixIn(UserPrincipal.class, UserPrincipalMixin.class)
                .build();

        var rowMapper = new JdbcOAuth2AuthorizationService
                .JsonMapperOAuth2AuthorizationRowMapper(registeredClientRepository, jsonMapper);
        service.setAuthorizationRowMapper(rowMapper);

        var parametersMapper = new JdbcOAuth2AuthorizationService
                .JsonMapperOAuth2AuthorizationParametersMapper(jsonMapper);
        service.setAuthorizationParametersMapper(parametersMapper);

        return new TrackingOAuth2AuthorizationService(service, refreshTokenRepository, registeredClientRepository);
    }

    private KeyPair generateRSAKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate RSA key", e);
        }
    }
}
