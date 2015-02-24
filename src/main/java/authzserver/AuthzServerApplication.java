package authzserver;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

@SpringBootApplication
public class AuthzServerApplication {

  public static void main(String[] args) {
    SpringApplication.run(AuthzServerApplication.class, args);
  }

  @Configuration
  @EnableAuthorizationServer
  protected static class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

    private static final String ROLE_TOKEN_CHECKER = "ROLE_TOKEN_CHECKER";

    @Autowired
    private DataSource dataSource;

    @Value("${oauthServer.accessTokenValiditySeconds}")
    private Integer accessTokenValiditySeconds;

    @Value("${oauthServer.refreshTokenValiditySeconds}")
    private Integer refreshTokenValiditySeconds;

    @Value("${oauthServer.approvalExpirySeconds}")
    private Integer approvalExpirySeconds;


    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints)
      throws Exception {

      final TokenStore tokenStore = new JdbcTokenStore(dataSource);
      final JdbcApprovalStore approvalStore = new JdbcApprovalStore(dataSource);

      final ApprovalStoreUserApprovalHandler userApprovalHandler = new ApprovalStoreUserApprovalHandler();
      userApprovalHandler.setApprovalStore(approvalStore);
      userApprovalHandler.setApprovalExpiryInSeconds(approvalExpirySeconds);

      final DefaultTokenServices tokenServices = new DefaultTokenServices();
      tokenServices.setSupportRefreshToken(true);
      tokenServices.setTokenStore(tokenStore);
      tokenServices.setAccessTokenValiditySeconds(accessTokenValiditySeconds);
      tokenServices.setRefreshTokenValiditySeconds(refreshTokenValiditySeconds);

      endpoints
        .tokenServices(tokenServices)
        .tokenStore(tokenStore)
        .approvalStore(approvalStore)
        .userApprovalHandler(userApprovalHandler)
        .authorizationCodeServices(new InMemoryAuthorizationCodeServices());
    }




    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
      oauthServer.checkTokenAccess("hasAuthority('" + ROLE_TOKEN_CHECKER + "')");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer configurer) throws Exception {
      configurer.jdbc(dataSource);
    }


  }
}
