package authzserver;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;

public class LifeCycleAPIAuthenticationManager implements AuthenticationManager {

  private String apiLifeCycleUsername;
  private String apiLifeCyclePassword;


  public LifeCycleAPIAuthenticationManager(String apiLifeCycleUsername, String apiLifeCyclePassword) {
    this.apiLifeCycleUsername = apiLifeCycleUsername;
    this.apiLifeCyclePassword = apiLifeCyclePassword;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String name = String.class.cast(authentication.getPrincipal());
    if (!name.equals(apiLifeCycleUsername)) {
      throw new UsernameNotFoundException("Unknown user: " + name);
    }
    if (!authentication.getCredentials().equals(apiLifeCyclePassword)) {
      throw new BadCredentialsException("Bad credentials");
    }
    return new UsernamePasswordAuthenticationToken(
      name,
      authentication.getCredentials(),
      Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
  }
}
