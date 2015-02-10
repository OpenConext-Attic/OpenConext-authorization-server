package authzserver.shibboleth;

import java.util.Enumeration;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

public class ShibbolethPreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

  private static final Logger LOG = LoggerFactory.getLogger(ShibbolethPreAuthenticatedProcessingFilter.class);

  @Override
  protected Object getPreAuthenticatedPrincipal(final HttpServletRequest request) {
    final Optional<String> uid = Optional.ofNullable(request.getHeader(ShibbolethRequestAttributes.UID.getAttributeName()));
    if (uid.isPresent()) {
      LOG.info("Found user with uid {}", uid.get());
      final String displayName = request.getHeader(ShibbolethRequestAttributes.DISPLAY_NAME.getAttributeName());
      return new ShibbolethPrincipal(uid.get(), displayName);
    } else {
      LOG.info("No principal found. This should have been set by shibboleth!");
      Enumeration<String> headerNames = request.getHeaderNames();
      while (headerNames.hasMoreElements()) {
        String name = headerNames.nextElement();
        LOG.info("Header name {} has value {}", name, request.getHeader(name));
      }

      return null;
    }
  }

  @Override
  protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
    return "N/A";
  }
}
