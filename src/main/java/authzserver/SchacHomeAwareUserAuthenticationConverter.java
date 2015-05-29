package authzserver;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;

import java.util.HashMap;
import java.util.Map;

import static authzserver.shibboleth.ShibbolethUserDetailService.ShibbolethUser;

public class SchacHomeAwareUserAuthenticationConverter extends DefaultUserAuthenticationConverter {

  @Override
  public Map<String, ?> convertUserAuthentication(Authentication authentication) {
    Map<String, ?> basic = super.convertUserAuthentication(authentication);
    ShibbolethUser shibbolethUser = (ShibbolethUser) authentication.getPrincipal();
    Map<String, Object> result = new HashMap<>(basic);

    result.put("schacHomeOrganization", shibbolethUser.getSchacHomeOrganization());
    result.put("authenticatingAuthority", shibbolethUser.getAuthenticatingAuthority());
    result.put("email", shibbolethUser.getEmail());
    return result;
  }

}
