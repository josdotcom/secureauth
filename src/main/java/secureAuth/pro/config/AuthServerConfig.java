package secureAuth.pro.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.jackson.SecurityJacksonModule;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import secureAuth.pro.repository.AuditLogRepository;
import secureAuth.pro.repository.RefreshTokenRepository;
import secureAuth.pro.repository.UserRepository;
import secureAuth.pro.security.*;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Configuration
@EnableMethodSecurity
public class AuthServerConfig {

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    RequestCache authorizeRequestCache() {
        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setRequestMatcher(request -> "/oauth2/authorize".equals(request.getRequestURI()));
        return requestCache;
    }

    @Bean @Order(1)
    SecurityFilterChain authServer(HttpSecurity http,
                                   RequestCache authorizeRequestCache,
                                   RegisteredClientRepository registeredClientRepository) throws Exception
    {

        MediaTypeRequestMatcher htmlMatcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
        htmlMatcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));   // curl sends Accept: */*, which
        // otherwise matches text/html

        http.oauth2AuthorizationServer(authServer -> {
                    http.securityMatcher(authServer.getEndpointsMatcher());
                    authServer.oidc(Customizer.withDefaults());
                    authServer.clientAuthentication(clientAuth -> clientAuth
                            .authenticationConverter(new PublicClientRefreshTokenAuthenticationConverter())
                            .authenticationProvider(new PublicClientRefreshTokenAuthenticationProvider(
                                    registeredClientRepository)));
                })
                .authorizeHttpRequests(a -> a.anyRequest().authenticated())
                .requestCache(cache -> cache.requestCache(authorizeRequestCache))
                .exceptionHandling(e -> e
                        // Order matters - entries are tried in insertion order. With only ONE mapping
                        // registered, Spring Security discards the matcher entirely and uses that entry
                        // point for everything, which is why /oauth2/token was answering machine requests
                        // with a 302 to the HTML login page.
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"), htmlMatcher)
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED), AnyRequestMatcher.INSTANCE));

        return http.build();
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new JwtClaimsAuthoritiesConverter());
        return converter;
    }

    @Bean
    @Order(2)
    SecurityFilterChain appSecurity(HttpSecurity http,
                                    TenantAuthenticationProvider tenantAuthenticationProvider,
                                    MfaAuthenticationSuccessHandler mfaSuccessHandler,
                                    RequestCache authorizeRequestCache) throws Exception {
        http
                // NOTE: form-action is deliberately ABSENT. An authorization server's login and MFA
                // forms must be able to complete a redirect chain that ends at a CLIENT's origin
                // (e.g. http://127.0.0.1:5173/callback). form-action 'self' governs the whole
                // form-submission navigation including redirects, so it silently blocks the final hop
                // for every cross-origin client while the server-side flow looks completely healthy.
                // Client redirect URIs are DB-driven, so a static allowlist cannot express them.
                // Keycloak's default CSP likewise omits form-action. Future work: a custom HeaderWriter
                // emitting "form-action 'self' <pending authorize request's redirect_uri origin>".
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'self';"
                                + "frame-ancestors 'none';"
                                + "style-src 'self' 'unsafe-inline'"
                        ))
                        .httpStrictTransportSecurity(hsts ->hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000)
                        )
                )
                .authenticationProvider(tenantAuthenticationProvider)
                .csrf(AbstractHttpConfigurer::disable)
                .requestCache(cache -> cache.requestCache(authorizeRequestCache))
                .authorizeHttpRequests(a -> a
                .requestMatchers("/api/register", "/api/login","/login", "/mfa").permitAll()
                .anyRequest().authenticated())
                .formLogin(form -> form.successHandler(mfaSuccessHandler))
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
    OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource,
                                           OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        jwtGenerator.setJwtCustomizer(tokenCustomizer);

        OAuth2TokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, new PublicClientRefreshTokenGenerator());
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
            RefreshTokenRepository refreshTokenRepository,
            AuditLogRepository auditLogRepository,
            UserRepository userRepository
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

        return new TrackingOAuth2AuthorizationService(service, refreshTokenRepository, registeredClientRepository, auditLogRepository, userRepository);
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
