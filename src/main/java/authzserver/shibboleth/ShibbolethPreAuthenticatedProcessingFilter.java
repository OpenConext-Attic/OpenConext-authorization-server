package authzserver.shibboleth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

public class ShibbolethPreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

  public static final String SHIB_NAME_ID_HEADER_NAME = "name-id";
  public static final String SHIB_SCHAC_HOME_ORGANIZATION_HEADER_NAME = "schachomeorganization";
  public static final String SHIB_AUTHENTICATING_AUTHORITY = "Shib-Authenticating-Authority";
  public static final String SHIB_EMAIL = "Shib-InetOrgPerson-mail";
  public static final String SHIB_DISPLAY_NAME = "displayName";
  public static final String SHIB_EDU_PERSON_PRINCIPAL_NAME = "eduPersonPrincipalName";

  private static final Logger LOG = LoggerFactory.getLogger(ShibbolethPreAuthenticatedProcessingFilter.class);
  private static final String EMPTY_HEADER_ERROR_TEMPLATE = "Header '%s' must be set";

  public ShibbolethPreAuthenticatedProcessingFilter(AuthenticationManager authenticationManager) {
    super();
    setAuthenticationManager(authenticationManager);
  }

  @Override
  protected Object getPreAuthenticatedPrincipal(final HttpServletRequest request) {
    String uid = request.getHeader(SHIB_NAME_ID_HEADER_NAME);
    if (StringUtils.isEmpty(uid)) {
      throw new PreAuthenticatedCredentialsNotFoundException(String.format(EMPTY_HEADER_ERROR_TEMPLATE, SHIB_NAME_ID_HEADER_NAME));
    }
    String schacHomeOrganization = request.getHeader(SHIB_SCHAC_HOME_ORGANIZATION_HEADER_NAME);
    if (StringUtils.isEmpty(schacHomeOrganization)) {
      throw new PreAuthenticatedCredentialsNotFoundException(String.format(EMPTY_HEADER_ERROR_TEMPLATE, SHIB_SCHAC_HOME_ORGANIZATION_HEADER_NAME));
    }
    String authenticatingAuthorities = request.getHeader(SHIB_AUTHENTICATING_AUTHORITY);
    if (StringUtils.isEmpty(authenticatingAuthorities)) {
      throw new PreAuthenticatedCredentialsNotFoundException(String.format(EMPTY_HEADER_ERROR_TEMPLATE, SHIB_AUTHENTICATING_AUTHORITY));
    }
    String authenticatingAuthority = authenticatingAuthorities.split(";")[0];

    String email = request.getHeader(SHIB_EMAIL);
    String displayName = request.getHeader("displayName");
    String eduPersonPrincipalName = request.getHeader("eduPersonPrincipalName");

    ShibbolethUser user = new ShibbolethUser(uid, eduPersonPrincipalName, schacHomeOrganization, displayName, authenticatingAuthority, email);
    LOG.debug("Assembled Shibboleth user from headers: {}", user);
    return user;
  }

  @Override
  protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
    return "N/A";
  }

}
