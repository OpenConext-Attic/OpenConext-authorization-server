package authzserver;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.ModelAndView;

import authzserver.shibboleth.ShibbolethUserDetailService;

/**
 * Customized endpoint to allow for i18n and a bit of branding.
 */
@Controller
@SessionAttributes("authorizationRequest")
public class CustomApprovalEndpoint {

  private static final Logger LOG = LoggerFactory.getLogger(CustomApprovalEndpoint.class);

  @Value("${confirmPage.logoUrl}")
  private String logoUrl;

  @Value("${confirmPage.appName}")
  private String appName;

  @RequestMapping("/oauth/confirm")
  public ModelAndView getAccessConfirmation(Map<String, Object> model, HttpServletRequest request, final PreAuthenticatedAuthenticationToken authentication) throws Exception {
    final ShibbolethUserDetailService.ShibbolethUser shibbolethUser = (ShibbolethUserDetailService.ShibbolethUser) authentication.getPrincipal();
    final AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get("authorizationRequest");
    LOG.debug("Displaying approval page for clientId {} to user {}", authorizationRequest.getClientId(), shibbolethUser.getUsername());

    if (request.getAttribute("_csrf") != null) {
      model.put("_csrf", request.getAttribute("_csrf"));
    }

    model.put("logoUrl", logoUrl);
    model.put("appName", appName);
    return new ModelAndView("confirm", model);
  }
}
