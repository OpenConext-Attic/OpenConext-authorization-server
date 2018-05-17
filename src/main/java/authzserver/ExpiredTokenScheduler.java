package authzserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
@EnableScheduling
public class ExpiredTokenScheduler {

  private static final Logger LOG = LoggerFactory.getLogger(ExpiredTokenScheduler.class);

  private boolean nodeCronJobResponsible;

  private ConcurrentJdbcTokenStore tokenStore;

  @Autowired
  public ExpiredTokenScheduler(@Value("${cron.node-cron-job-responsible}") boolean nodeCronJobResponsible,
                               ConcurrentJdbcTokenStore tokenStore) {
    this.nodeCronJobResponsible = nodeCronJobResponsible;
    this.tokenStore = tokenStore;
  }

  @Scheduled(cron = "${cron.expression}")
  public Map<String, ?> scheduled() {
    if (nodeCronJobResponsible) {
      Map<String, Integer> result = new HashMap<>();
      try {
        result.put("oauth_access_token", this.removeExpiredAccessTokens());
        result.put("oauth_refresh_token", this.removeExpiredRefreshTokens());
        result.put("oauth_code", this.removeExpiredAuthorizationCodes());
        result.put("oauth_approvals", this.removeExpiredApprovals());
        return result;
      } catch (Throwable t) { //NOSONAR
        //deliberate swallowing because otherwise the scheduler stops
        LOG.error("Unexpected exception in removing expired tokens", t);
        return Collections.singletonMap("error", t);
      }
    }
    return null;
  }

  private int removeExpiredAccessTokens() {
    List<OAuth2AccessToken> oAuth2AccessTokens = this.tokenStore.allOAuth2AccessTokens();
    List<OAuth2AccessToken> tokens = oAuth2AccessTokens.stream().filter(token
      -> token.isExpired()).collect(Collectors.toList());
    tokens.forEach(token -> {
      this.tokenStore.removeAccessToken(token);
      LOG.info("Deleted access token {} because it was expired", token.getValue());
    });
    LOG.info("Deleted {} access tokens because they were expired", tokens.size());
    return tokens.size();
  }

  private int removeExpiredRefreshTokens() {
    List<ExpiringOAuth2RefreshToken> tokens = this.tokenStore.allOAuth2RefreshTokens().stream()
      .filter(token -> token.getExpiration() != null && token.getExpiration().before(new Date()))
      .collect(Collectors.toList());
      tokens.forEach(token -> {
        this.tokenStore.removeRefreshToken(token);
        LOG.info("Deleted refresh token {} because it was expired", token.getValue());
      });
    LOG.info("Deleted {} refresh tokens because they were expired", tokens.size());
    return tokens.size();
  }

  private int removeExpiredAuthorizationCodes() {
    int updated = this.tokenStore.removeExpiredAuthorizationCodes();
    LOG.info("Removed {} expired authorization codes", updated);
    return updated;
  }

  private int removeExpiredApprovals() {
    int updated = this.tokenStore.removeExpiredApprovals();
    LOG.info("Removed {} expired approvals", updated);
    return updated;
  }
}
