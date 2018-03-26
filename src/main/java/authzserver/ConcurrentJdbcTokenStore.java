package authzserver;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import javax.sql.DataSource;

public class ConcurrentJdbcTokenStore extends JdbcTokenStore {

  public ConcurrentJdbcTokenStore(DataSource dataSource) {
    super(dataSource);
  }

  @Override
  public void removeAccessToken(String tokenValue) {
    try {
      super.removeAccessToken(tokenValue);
    } catch (RuntimeException e) {
      //try once more
      super.removeAccessToken(tokenValue);
    }

  }

  @Override
  public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
    try {
      super.storeAccessToken(token, authentication);
    } catch (DuplicateKeyException e) {
      /*
       * Yep that is right... This happens under load when multiple client_credentials calls for the same user are done.
       * See: https://github.com/spring-projects/spring-security-oauth/issues/1242
       */
    }

  }
}
