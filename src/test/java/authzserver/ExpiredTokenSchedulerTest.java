package authzserver;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.util.Calendar;
import java.util.Map;

import static java.util.Collections.EMPTY_LIST;
import static java.util.Collections.EMPTY_MAP;
import static java.util.Collections.EMPTY_SET;
import static org.junit.Assert.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
  properties = {"cron.node-cron-job-responsible=false"})
public class ExpiredTokenSchedulerTest extends AbstractIntegrationTest {

  @Autowired
  private ConcurrentJdbcTokenStore tokenStore;

  @Test
  public void scheduled() {
    Calendar now = Calendar.getInstance();
    now.add(Calendar.YEAR, -100);

    DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("value");
    token.setExpiration(now.getTime());

    OAuth2Request request = new OAuth2Request(EMPTY_MAP, "clientId", EMPTY_LIST, true, EMPTY_SET,
      EMPTY_SET, "http://redirectUri", EMPTY_SET, EMPTY_MAP);
    Authentication userAuthentication = new UsernamePasswordAuthenticationToken("principal", "credentials");
    OAuth2Authentication authentication = new OAuth2Authentication(request, userAuthentication);

    tokenStore.storeAccessToken(token, authentication);

    OAuth2RefreshToken refreshToken = new DefaultExpiringOAuth2RefreshToken("value", now.getTime());
    tokenStore.storeRefreshToken(refreshToken, authentication);

    tokenStore.getJdbcTemplate().update("INSERT INTO oauth_approvals " +
      "(userId, clientId, scope, status, expiresAt, lastModifiedAt)" +
      "VALUES" +
      "('user', 'client', 'read', 'APPROVED', '2016-05-09 14:21:31', '2018-05-14 14:21:31')", EMPTY_MAP);
    tokenStore.getJdbcTemplate().update("INSERT INTO oauth_code " +
      "(code, authentication, created) VALUES ('code', '', '2016-05-17 14:50:24')", EMPTY_MAP);
    
    
    ExpiredTokenScheduler scheduler = new ExpiredTokenScheduler(true, tokenStore);
    Map<String, ?> scheduled = scheduler.scheduled();
    assertEquals(1, scheduled.get("oauth_access_token"));
    assertEquals(1, scheduled.get("oauth_refresh_token"));
    assertEquals(1, scheduled.get("oauth_code"));
    assertEquals(1, scheduled.get("oauth_approvals"));

  }
}
