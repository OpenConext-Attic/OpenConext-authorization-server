package authzserver.shibboleth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;

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
    String uid = getHeader(SHIB_NAME_ID_HEADER_NAME, request);
    if (StringUtils.isEmpty(uid)) {
      throw new PreAuthenticatedCredentialsNotFoundException(String.format(EMPTY_HEADER_ERROR_TEMPLATE, SHIB_NAME_ID_HEADER_NAME));
    }
    String schacHomeOrganization = getHeader(SHIB_SCHAC_HOME_ORGANIZATION_HEADER_NAME, request);
    if (StringUtils.isEmpty(schacHomeOrganization)) {
      throw new PreAuthenticatedCredentialsNotFoundException(String.format(EMPTY_HEADER_ERROR_TEMPLATE, SHIB_SCHAC_HOME_ORGANIZATION_HEADER_NAME));
    }
    String authenticatingAuthorities = getHeader(SHIB_AUTHENTICATING_AUTHORITY, request);
    if (StringUtils.isEmpty(authenticatingAuthorities)) {
      throw new PreAuthenticatedCredentialsNotFoundException(String.format(EMPTY_HEADER_ERROR_TEMPLATE, SHIB_AUTHENTICATING_AUTHORITY));
    }
    String authenticatingAuthority = authenticatingAuthorities.split(";")[0];

    String email = getHeader(SHIB_EMAIL, request);
    String displayName = getHeader("displayName", request);
    String eduPersonPrincipalName = getHeader("eduPersonPrincipalName", request);

    ShibbolethUser user = new ShibbolethUser(uid, eduPersonPrincipalName, schacHomeOrganization, displayName, authenticatingAuthority, email);
    LOG.debug("Assembled Shibboleth user from headers: {}", user);
    return user;
  }

  @Override
  protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
    return "N/A";
  }

  private String getHeader(String name, HttpServletRequest request) {
    String header = request.getHeader(name);
    try {
      return StringUtils.hasText(header) ?
        new String(header.getBytes("ISO8859-1"), "UTF-8") : header;
    } catch (UnsupportedEncodingException e) {
      throw new IllegalArgumentException(e);
    }
  }


}
