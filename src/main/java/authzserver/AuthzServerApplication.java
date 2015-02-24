package authzserver;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
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

    @Bean
    @Scope("singleton")
    TokenStore tokenStore() {
      return new JdbcTokenStore(dataSource);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints)
      throws Exception {
      endpoints
        .tokenStore(tokenStore())
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

    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
      DefaultTokenServices tokenServices = new DefaultTokenServices();
      tokenServices.setSupportRefreshToken(true);
      tokenServices.setTokenStore(tokenStore());
      return tokenServices;
    }
  }
}
