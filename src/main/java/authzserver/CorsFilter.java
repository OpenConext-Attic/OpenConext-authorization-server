package authzserver;

import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*
 * We deliberately have a lenient CORS policy as we restrict access using the Oauth2 API
 */
public class CorsFilter extends GenericFilterBean {

  private String maxAge = String.valueOf(60 * 60 * 24 * 20);

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;

    response.setHeader("Access-Control-Allow-Origin", "*");
    response.setHeader("Access-Control-Allow-Methods", "*");
    response.setHeader("Access-Control-Allow-Credentials", "true");
    response.setHeader("Access-Control-Max-Age", maxAge);

    String header = request.getHeader("Access-Control-Request-Headers");
    if (StringUtils.hasText(header)) {
      response.setHeader("Access-Control-Allow-Headers", header);
    }

    if (request.getMethod().toLowerCase().equals("options") && request.getHeader("Access-Control-Request-Method") != null) {
      response.setStatus(HttpStatus.OK.value());
    } else {
      chain.doFilter(req, res);
    }

  }

}
