package authzserver.shibboleth;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import authzserver.shibboleth.ShibbolethPreAuthenticatedProcessingFilter.ShibbolethPrincipal;

public class ShibbolethUserDetailService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

  /**
   * Instances of this class gets serialized and stored in the database by spring-security-oauth (the authentication column)
   * Therefore, when you change this class, you should be aware that pre-existing tokens must be deleted, unless you implement
   * some form of automatic migration.
   */
  public static class ShibbolethUser implements UserDetails {

    private static final long serialVersionUID = 2l;

    private final String username;
    private final String schacHomeOrganization;

    @Override
    public String toString() {
      return "ShibbolethUser{" +
        "username='" + username + '\'' +
        ", schacHomeOrganization='" + schacHomeOrganization + '\'' +
        '}';
    }

    public ShibbolethUser(String username, String schacHomeOrganization) {
      this.username = username;
      this.schacHomeOrganization = schacHomeOrganization;
    }

    public String getSchacHomeOrganization() {
      return schacHomeOrganization;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
      return Collections.unmodifiableList(Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Override
    public String getPassword() {
      return null;
    }

    @Override
    public String getUsername() {
      return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
      return true;
    }

    @Override
    public boolean isAccountNonLocked() {
      return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
      return true;
    }

    @Override
    public boolean isEnabled() {
      return true;
    }
  }

  @Override
  public UserDetails loadUserDetails(final PreAuthenticatedAuthenticationToken authentication) throws UsernameNotFoundException {
    ShibbolethPrincipal shibbolethPrincipal = (ShibbolethPrincipal) authentication.getPrincipal();
    return new ShibbolethUser(shibbolethPrincipal.username, shibbolethPrincipal.schacHomeOrganization);
  }
}
