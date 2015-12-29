package authzserver;

import authzserver.shibboleth.ShibbolethUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;

import java.util.HashMap;
import java.util.Map;


public class SchacHomeAwareUserAuthenticationConverter extends DefaultUserAuthenticationConverter {

  @Override
  public Map<String, ?> convertUserAuthentication(Authentication authentication) {
    Map<String, ?> basic = super.convertUserAuthentication(authentication);
    ShibbolethUser shibbolethUser = (ShibbolethUser) authentication.getPrincipal();
    Map<String, Object> result = new HashMap<>(basic);

    result.put("schacHomeOrganization", shibbolethUser.getSchacHomeOrganization());
    result.put("authenticatingAuthority", shibbolethUser.getAuthenticatingAuthority());
    result.put("email", shibbolethUser.getEmail());
    result.put("eduPersonPrincipalName", shibbolethUser.getEduPersonPrincipalName());
    result.put("displayName", shibbolethUser.getDisplayName());
    return result;
  }

}
