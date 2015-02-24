package authzserver.shibboleth;

import java.io.Serializable;
import java.util.Enumeration;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;

public class ShibbolethPreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

  public static final String UID_HEADER_NAME = "uid";
  public static final String SCHACH_HOME_ORGANIZATION_HEADER_NAME = "schachomeorganization";
  public static final String DISPLAY_NAME_HEADER_NAME = "displayname";

  private static final Logger LOG = LoggerFactory.getLogger(ShibbolethPreAuthenticatedProcessingFilter.class);
  private static final String EMPTY_HEADER_ERROR_TEMPLATE = "Header '%s' must be set";

  public ShibbolethPreAuthenticatedProcessingFilter(AuthenticationManager authenticationManager) {
    super();
    setAuthenticationManager(authenticationManager);
  }

  /**
   * @param request
   * @return ShibbolethPrincipal
   * @throws java.lang.IllegalArgumentException when any of the required headers is not present.
   */
  @Override
  protected Object getPreAuthenticatedPrincipal(final HttpServletRequest request) {
    String uid = request.getHeader(UID_HEADER_NAME);
    Preconditions.checkArgument(!Strings.isNullOrEmpty(uid), EMPTY_HEADER_ERROR_TEMPLATE, UID_HEADER_NAME);

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

  public final static class ShibbolethPrincipal implements Serializable {
    public final String uid;
    public final String schacHomeOrganization;
    public final String displayName;

    public ShibbolethPrincipal(String uid, String schacHomeOrganization, String displayName) {
      this.uid = uid;
      this.schacHomeOrganization = schacHomeOrganization;
      this.displayName = displayName;
    }

    @Override
    public String toString() {
      return "ShibbolethPrincipal{" +
        "uid='" + uid + '\'' +
        ", schacHomeOrganization='" + schacHomeOrganization + '\'' +
        ", displayName='" + displayName + '\'' +
        '}';
    }
  }
}
