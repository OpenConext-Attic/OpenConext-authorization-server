package authzserver.shibboleth;

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
      return uid.get();
    } else {
      return null;
    }
  }

  @Override
  protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
    return "N/A";
  }
}
