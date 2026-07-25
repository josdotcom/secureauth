package secureAuth.pro.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class JwtClaimsAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final String AUTHORITIES_CLAIM = "authorities";
    private static final String ROLES_CLAIM = "roles";
    private static final String ROLE_PREFIX = "ROLE_";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        List<GrantedAuthority> authorities = new ArrayList<>();

        List<String> permissionClaims = jwt.getClaimAsStringList(AUTHORITIES_CLAIM);
        if (permissionClaims != null) {
            for (String permission: permissionClaims) {
                authorities.add(new SimpleGrantedAuthority(permission));
            }
        }

        List<String> rolesClaims = jwt.getClaimAsStringList(ROLES_CLAIM);
        if (rolesClaims != null) {
            for (String role: rolesClaims) {
                authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role));
            }
        }

        return authorities;
    }
}
