package authzserver.shibboleth;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;

public class ShibbolethPreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

  public static final String COLLAB_PERSON_ID_HEADER_NAME = "name-id";
  public static final String SCHAC_HOME_ORGANIZATION_HEADER_NAME = "schachomeorganization";
  public static final String DISPLAY_NAME_HEADER_NAME = "displayname";
  public static final String PERSISTENT_NAME_ID_PREFIX = "urn:collab:person:";
  public static final String SHIB_AUTHENTICATING_AUTHORITY = "Shib-Authenticating-Authority";

  private static final Logger LOG = LoggerFactory.getLogger(ShibbolethPreAuthenticatedProcessingFilter.class);
  private static final String EMPTY_HEADER_ERROR_TEMPLATE = "Header '%s' must be set";

  public ShibbolethPreAuthenticatedProcessingFilter(AuthenticationManager authenticationManager) {
    super();
    setAuthenticationManager(authenticationManager);
  }

  @Override
  protected Object getPreAuthenticatedPrincipal(final HttpServletRequest request) {
    String uid = request.getHeader(COLLAB_PERSON_ID_HEADER_NAME);
    Preconditions.checkArgument(!Strings.isNullOrEmpty(uid), EMPTY_HEADER_ERROR_TEMPLATE, COLLAB_PERSON_ID_HEADER_NAME);
    Preconditions.checkArgument(uid.startsWith(PERSISTENT_NAME_ID_PREFIX), "Header '%s' must start with '%s'. Actual value is '%'", COLLAB_PERSON_ID_HEADER_NAME, PERSISTENT_NAME_ID_PREFIX, uid);

    String schacHomeOrganization = request.getHeader(SCHAC_HOME_ORGANIZATION_HEADER_NAME);
    Preconditions.checkArgument(!Strings.isNullOrEmpty(schacHomeOrganization), EMPTY_HEADER_ERROR_TEMPLATE, SCHAC_HOME_ORGANIZATION_HEADER_NAME);

    String email = request.getHeader("Shib-InetOrgPerson-mail");

    String displayName = request.getHeader(DISPLAY_NAME_HEADER_NAME);

    String authenticatingAuthorities = request.getHeader(SHIB_AUTHENTICATING_AUTHORITY);
    Preconditions.checkArgument(!Strings.isNullOrEmpty(authenticatingAuthorities), EMPTY_HEADER_ERROR_TEMPLATE, SHIB_AUTHENTICATING_AUTHORITY);
    String authenticatingAuthority = authenticatingAuthorities.split(";")[0];

    final ShibbolethPrincipal shibbolethPrincipal = new ShibbolethPrincipal(uid, schacHomeOrganization, displayName, authenticatingAuthority, email);
    LOG.debug("Assembled Shibboleth principal from headers: {}", shibbolethPrincipal);
    return shibbolethPrincipal;
  }

  @Override
  protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
    return "N/A";
  }

  public final static class ShibbolethPrincipal {

    public final String username;
    public final String schacHomeOrganization;
    public final String displayName;
    public final String authenticatingAuthority;
    public final String email;

    public ShibbolethPrincipal(String username, String schacHomeOrganization, String displayName, String authenticatingAuthority, String email) {
      this.username = username;
      this.schacHomeOrganization = schacHomeOrganization;
      this.displayName = displayName;
      this.authenticatingAuthority = authenticatingAuthority;
      this.email = email;
    }

    @Override
    public String toString() {
      return "ShibbolethPrincipal{" +
        "username='" + username + '\'' +
        ", schacHomeOrganization='" + schacHomeOrganization + '\'' +
        ", displayName='" + displayName + '\'' +
        ", authenticatingAuthority='" + authenticatingAuthority + '\'' +
        ", email='" + email + '\'' +
        '}';
    }
  }
}
