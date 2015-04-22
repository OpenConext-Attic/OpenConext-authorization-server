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
    private final String displayName;
    private final String authenticatingAuthority;
    private final String email;

    @Override
    public String toString() {
      return "ShibbolethUser{" +
        "username='" + username + '\'' +
        ", schacHomeOrganization='" + schacHomeOrganization + '\'' +
        ", displayName='" + displayName + '\'' +
        ", authenticatingAuthority='" + authenticatingAuthority + '\'' +
        ", email='" + email + '\'' +
        '}';
    }

    public ShibbolethUser(String username, String schacHomeOrganization, String displayName, String authenticatingAuthority, String email) {
      this.username = username;
      this.schacHomeOrganization = schacHomeOrganization;
      this.displayName = displayName;
      this.authenticatingAuthority = authenticatingAuthority;
      this.email = email;
    }

    public String getSchacHomeOrganization() {
      return schacHomeOrganization;
    }

    public String getDisplayName() {
      return displayName;
    }

    public String getAuthenticatingAuthority() {
      return authenticatingAuthority;
    }

    public String getEmail() {
      return email;
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
    return new ShibbolethUser(shibbolethPrincipal.username, shibbolethPrincipal.schacHomeOrganization, shibbolethPrincipal.displayName, shibbolethPrincipal.authenticatingAuthority, shibbolethPrincipal.email);
  }
}
