package authzserver.mock;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import authzserver.shibboleth.ShibbolethRequestAttributes;

public class MockShibbolethFilter implements Filter {

  private static class SetHeader extends HttpServletRequestWrapper {

    private final HashMap<String, String> headers;

    public SetHeader(HttpServletRequest request) {
      super(request);
      this.headers = new HashMap<>();
    }

    public void setHeader(String name, String value) {
      this.headers.put(name, value);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
      List<String> names = Collections.list(super.getHeaderNames());
      names.addAll(headers.keySet());
      return Collections.enumeration(names);
    }

    @Override
    public String getHeader(String name) {
      if (headers.containsKey(name)) {
        return headers.get(name);
      }
      return super.getHeader(name);
    }
  }

  private static final Logger LOG = LoggerFactory.getLogger(MockShibbolethFilter.class);

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    LOG.info("=================================");
    LOG.info("MockShibbolethFilter initialized!");
    LOG.info("=================================");
  }

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
    SetHeader wrapper = new SetHeader((HttpServletRequest) servletRequest);
    wrapper.setHeader(ShibbolethRequestAttributes.UID.getAttributeName(), "saml2_user");
    wrapper.setHeader(ShibbolethRequestAttributes.DISPLAY_NAME.getAttributeName(), "SAML2 Auth. User");
    LOG.info("ShibbolethRequestAttributes set on servletRequest!");
    filterChain.doFilter(wrapper, servletResponse);
  }

  @Override
  public void destroy() {

  }
}
