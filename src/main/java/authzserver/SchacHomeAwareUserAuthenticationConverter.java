package authzserver;

import static authzserver.shibboleth.ShibbolethUserDetailService.ShibbolethUser;

import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;

import com.google.common.collect.ImmutableMap;

public class SchacHomeAwareUserAuthenticationConverter extends DefaultUserAuthenticationConverter {

  @Override
  public Map<String, ?> convertUserAuthentication(final Authentication authentication) {
    final Map<String, ?> basic = super.convertUserAuthentication(authentication);
    final ShibbolethUser shibbolethUser = (ShibbolethUser) authentication.getPrincipal();
    return ImmutableMap.<String, Object>builder().
      putAll(basic).
      put("schacHomeOrganization", shibbolethUser.getSchacHomeOrganization()).
      put("email", shibbolethUser.getEmail()).
      put("authenticatingAuthority", shibbolethUser.getAuthenticatingAuthority()).
      build();
  }

}
