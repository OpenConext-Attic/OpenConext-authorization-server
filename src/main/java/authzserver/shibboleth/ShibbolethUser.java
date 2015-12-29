package authzserver.shibboleth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
/**
 * Instances of this class gets serialized and stored in the database by spring-security-oauth (the authentication column)
 * Therefore, when you change this class, you should be aware that pre-existing tokens must be deleted, unless you implement
 * some form of automatic migration.
 */
public class ShibbolethUser extends User {

  private final String eduPersonPrincipalName;
  private final String schacHomeOrganization;
  private final String displayName;
  private final String authenticatingAuthority;
  private final String email;

  public ShibbolethUser(String username, String eduPersonPrincipalName, String schacHomeOrganization, String displayName, String authenticatingAuthority, String email) {
    super(username, "N/A", Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
    this.eduPersonPrincipalName = eduPersonPrincipalName;
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

  public String getEduPersonPrincipalName() {
    return eduPersonPrincipalName;
  }
}
