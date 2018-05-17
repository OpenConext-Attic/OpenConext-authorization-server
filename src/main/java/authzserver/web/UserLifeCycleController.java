package authzserver.web;

import authzserver.model.Attribute;
import authzserver.model.LifeCycleResult;
import authzserver.shibboleth.ShibbolethUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Collections.singletonMap;

@RestController
public class UserLifeCycleController {

  private static final Logger LOG = LoggerFactory.getLogger(UserLifeCycleController.class);

  private NamedParameterJdbcTemplate jdbcTemplate;

  @Autowired
  public UserLifeCycleController(DataSource dataSource) {
    this.jdbcTemplate = new NamedParameterJdbcTemplate(dataSource);
  }

  @RequestMapping(method = RequestMethod.GET, value = "/deprovision/{userId:.+}")
  public LifeCycleResult preview(@PathVariable String userId, Authentication authentication) {
    LOG.info("Request for lifecycle preview for {} by {}", userId, authentication.getPrincipal());

    return doDryRun(userId, true);
  }

  @RequestMapping(method = RequestMethod.DELETE, value = "/deprovision/{userId:.+}/dry-run")
  public LifeCycleResult dryRun(@PathVariable String userId, Authentication authentication) {
    LOG.info("Request for lifecycle dry-run for {} by {}", userId, authentication.getPrincipal());

    return doDryRun(userId, true);
  }

  @RequestMapping(method = RequestMethod.DELETE, value = "/deprovision/{userId:.+}")
  @Transactional
  public LifeCycleResult deprovision(@PathVariable String userId, Authentication authentication) {
    LOG.info("Request for lifecycle deprovision for {} by {}", userId, authentication.getPrincipal());

    return doDryRun(userId, false);
  }

  private LifeCycleResult doDryRun(String userId, boolean dryRun) {
    LifeCycleResult result = new LifeCycleResult();
    Set<Attribute> attributes = new HashSet<>();
    Map<String, String> paramMap = singletonMap("user_name", userId);
    List<String> refreshTokens = new ArrayList<>();

    jdbcTemplate.query("select authentication, refresh_token from " +
        "oauth_access_token where user_name = :user_name",
      paramMap, rs -> {
        OAuth2Authentication oAuth2Authentication = SerializationUtils.deserialize(rs.getBytes(1));
        addUserAttributes(attributes, oAuth2Authentication);
        refreshTokens.add(rs.getString(2));
      });
    if (!refreshTokens.isEmpty()) {
      jdbcTemplate.query("select authentication from oauth_refresh_token where token_id in (:tokens)", singletonMap
        ("tokens", refreshTokens), rs -> {
        OAuth2Authentication oAuth2Authentication = SerializationUtils.deserialize(rs.getBytes(1));
        addUserAttributes(attributes, oAuth2Authentication);
      });
    }
    jdbcTemplate.query("select clientId, scope, status from oauth_approvals where userId = :user_name",
      paramMap, rs -> {
        attributes.add(new Attribute("approval", rs.getString(1) + "_" +
          rs.getString(2) + "_" + rs.getString(3)));
      });
    if (!dryRun) {
      int update = jdbcTemplate.update("delete from oauth_approvals where userId = :user_name", paramMap);
      LOG.info("Removed {} oauth_approvals for user {}", update, userId);

      if (!refreshTokens.isEmpty()) {
        update = jdbcTemplate.update("delete from oauth_refresh_token where token_id in (:tokens)",
          singletonMap("tokens", refreshTokens));
        LOG.info("Removed {} oauth_refresh_token for user {}", update, userId);
      }
      update = jdbcTemplate.update("delete from oauth_access_token where user_name = :user_name", paramMap);
      LOG.info("Removed {} oauth_access_token for user {}", update, userId);
    }

    result.setData(new ArrayList<>(attributes).stream()
      .filter(attr -> StringUtils.hasText(attr.getValue()))
      .sorted(Comparator.comparing(Attribute::getName))
      .collect(Collectors.toList()));
    return result;
  }

  private void addUserAttributes(Set<Attribute> attributes, OAuth2Authentication oAuth2Authentication) {
    ShibbolethUser user = ShibbolethUser.class.cast(oAuth2Authentication.getPrincipal());
    attributes.add(new Attribute("authenticating_authority", user.getAuthenticatingAuthority()));
    attributes.add(new Attribute("display_name", user.getDisplayName()));
    attributes.add(new Attribute("edu_person_principal_name", user.getEduPersonPrincipalName()));
    attributes.add(new Attribute("email", user.getEmail()));
    attributes.add(new Attribute("schac_home_organisation", user.getSchacHomeOrganization()));
    attributes.add(new Attribute("user_name", user.getUsername()));
  }

}
