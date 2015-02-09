package authzserver;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@SpringBootApplication
public class AuthzServerApplication {

  public static void main(String[] args) {
    SpringApplication.run(AuthzServerApplication.class, args);
  }


  @Configuration
  @EnableWebSecurity
  @EnableWebMvcSecurity
  protected static class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      User user = new User("foo", "bar", Collections.<GrantedAuthority>emptyList());
      auth.userDetailsService(new InMemoryUserDetailsManager(Arrays.asList(user)));
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
      return super.authenticationManagerBean();
    }

  }

  @Configuration
  @EnableAuthorizationServer
  protected static class AuthorizationServerConfiguration extends
    AuthorizationServerConfigurerAdapter {

    private TokenStore tokenStore = new InMemoryTokenStore();

    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints)
      throws Exception {
      // @formatter:off
      endpoints
        .tokenStore(this.tokenStore)
        .authenticationManager(this.authenticationManager);
      // @formatter:on
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
      // @formatter:off
      clients
        .inMemory()
        .withClient("clientapp")
        .authorizedGrantTypes("password", "refresh_token")
        .authorities("USER")
        .scopes("read", "write")
        .resourceIds("groups-service")
        .secret("123456");
      // @formatter:on
    }

    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
      DefaultTokenServices tokenServices = new DefaultTokenServices();
      tokenServices.setSupportRefreshToken(true);
      tokenServices.setTokenStore(this.tokenStore);
      return tokenServices;
    }

  }
}
