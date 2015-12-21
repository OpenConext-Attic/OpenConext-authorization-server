package authzserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Customized endpoint to allow for i18n and a bit of branding.
 */
@Controller
@SessionAttributes("authorizationRequest")
public class CustomApprovalEndpoint {

  private static final Logger LOG = LoggerFactory.getLogger(CustomApprovalEndpoint.class);
  private final Environment environment;

  @Autowired
  public CustomApprovalEndpoint(Environment environment) {
    this.environment = environment;
  }

  @Value("${confirmPage.appName}")
  private String appName;

  @RequestMapping("/oauth/confirm")
  public ModelAndView getAccessConfirmation(Map<String, Object> model, HttpServletRequest request, final PreAuthenticatedAuthenticationToken authentication) throws Exception {
    final AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get("authorizationRequest");
    if (environment.acceptsProfiles("dev") && authorizationRequest == null) {
      development(model, request);
    }

    if (request.getAttribute("_csrf") != null) {
      model.put("_csrf", request.getAttribute("_csrf"));
    }

    model.put("appName", appName);
    return new ModelAndView("confirm", model);
  }

  /*
   * Enables testing - e.g. styling - against http://localhost:8080/oauth/confirm
   */
  private void development(Map<String, Object> model, HttpServletRequest request) {
    LOG.debug("Adding a mock authorization request to the model");
    model.put("authorizationRequest", new AuthorizationRequest("client_id", Collections.singletonList("groups")));
    Map<String, Object> scopes = new LinkedHashMap<>();
    scopes.put("scope.groups", false);
    request.setAttribute("scopes", scopes);
  }
}
