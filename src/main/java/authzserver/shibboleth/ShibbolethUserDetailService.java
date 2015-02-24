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

  public static class ShibbolethUser implements UserDetails {

    private final String uid;
    private final String schacHomeOrganization;
    private final String displayName;

    @Override
    public String toString() {
      return "ShibbolethUser{" +
        "uid='" + uid + '\'' +
        ", schacHomeOrganization='" + schacHomeOrganization + '\'' +
        ", displayName='" + displayName + '\'' +
        '}';
    }

    public ShibbolethUser(String uid, String schacHomeOrganization, String displayName) {
      this.uid = uid;
      this.schacHomeOrganization = schacHomeOrganization;
      this.displayName = displayName;
    }

    public String getUid() {
      return uid;
    }

    public String getSchacHomeOrganization() {
      return schacHomeOrganization;
    }

    public String getDisplayName() {
      return displayName;
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
      return this.uid;
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
    return new ShibbolethUser(shibbolethPrincipal.uid, shibbolethPrincipal.schacHomeOrganization, shibbolethPrincipal.displayName);
  }
}
