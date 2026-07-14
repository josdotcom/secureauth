package secureAuth.pro.security;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.UUID;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonAutoDetect(
        fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE
)
public abstract class UserPrincipalMixin {
    @JsonCreator
    UserPrincipalMixin(
            @JsonProperty("userId") UUID userId,
            @JsonProperty("email") String email,
            @JsonProperty("passwordHash") String passwordHash,
            @JsonProperty("tenantId") UUID tenantId,
            @JsonProperty("enabled") boolean enabled,
            @JsonProperty("locked") boolean locked,
            @JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities
    ){

    }
}
