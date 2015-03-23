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
  public static final String SCHACH_HOME_ORGANIZATION_HEADER_NAME = "schachomeorganization";
  public static final String DISPLAY_NAME_HEADER_NAME = "displayname";
  public static final String PERSISTENT_NAME_ID_PREFIX = "urn:collab:person:";

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

    String schacHomeOrganization = request.getHeader(SCHACH_HOME_ORGANIZATION_HEADER_NAME);
    Preconditions.checkArgument(!Strings.isNullOrEmpty(schacHomeOrganization), EMPTY_HEADER_ERROR_TEMPLATE, SCHACH_HOME_ORGANIZATION_HEADER_NAME);

    String displayName = request.getHeader(DISPLAY_NAME_HEADER_NAME);
    Preconditions.checkArgument(!Strings.isNullOrEmpty(displayName), EMPTY_HEADER_ERROR_TEMPLATE, DISPLAY_NAME_HEADER_NAME);

    final ShibbolethPrincipal shibbolethPrincipal = new ShibbolethPrincipal(uid, schacHomeOrganization, displayName);
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

    public ShibbolethPrincipal(String username, String schacHomeOrganization, String displayName) {
      this.username = username;
      this.schacHomeOrganization = schacHomeOrganization;
      this.displayName = displayName;
    }

    @Override
    public String toString() {
      return "ShibbolethPrincipal{" +
        "username='" + username + '\'' +
        ", schacHomeOrganization='" + schacHomeOrganization + '\'' +
        ", displayName='" + displayName + '\'' +
        '}';
    }
  }
}
