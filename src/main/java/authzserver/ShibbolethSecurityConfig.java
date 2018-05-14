package authzserver;

import authzserver.mock.MockShibbolethFilter;
import authzserver.shibboleth.ShibbolethPreAuthenticatedProcessingFilter;
import authzserver.shibboleth.ShibbolethUserDetailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class ShibbolethSecurityConfig extends WebSecurityConfigurerAdapter {

  private static final Logger LOG = LoggerFactory.getLogger(ShibbolethSecurityConfig.class);

  @Order(1)
  @Configuration
  public static class LifeCycleSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

    @Value("${api.lifecycle.username}")
    private String apiLifeCycleUsername;

    @Value("${api.lifecycle.password}")
    private String apiLifeCyclePassword;


    @Override
    public void configure(HttpSecurity http) throws Exception {
      http
        .antMatcher("/deprovision/**")
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.NEVER)
        .and()
        .csrf()
        .disable()
        .addFilterBefore(
          new BasicAuthenticationFilter(
            new LifeCycleAPIAuthenticationManager(apiLifeCycleUsername, apiLifeCyclePassword)
          ), BasicAuthenticationFilter.class
        )
        .authorizeRequests()
        .antMatchers("/deprovision/**").hasRole("USER");
    }

  }

  @Configuration
  @Order(2)
  public static class GeneralSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
    @Autowired
    private Environment environment;

    @Override
    public void configure(WebSecurity web) throws Exception {
      web.
        ignoring()
        .antMatchers("/static/**")
        .antMatchers("/info")
        .antMatchers("/health");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      http
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
        .and()
        .addFilterBefore(new ShibbolethPreAuthenticatedProcessingFilter(authenticationManagerBean()),
          AbstractPreAuthenticatedProcessingFilter.class)
        .authorizeRequests()
        .antMatchers("/oauth/authorize").hasAnyRole("USER");

      //we want to specify the exact order and RegistrationBean#setOrder does not support pinpointing the order
      // before class
      //see https://github.com/spring-projects/spring-boot/issues/1640
      if (environment.acceptsProfiles("dev")) {
        http.addFilterBefore(new MockShibbolethFilter(), ShibbolethPreAuthenticatedProcessingFilter.class);
      }
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      LOG.info("Configuring AuthenticationManager with a PreAuthenticatedAuthenticationProvider");
      PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
      authenticationProvider.setPreAuthenticatedUserDetailsService(new ShibbolethUserDetailService());
      auth.authenticationProvider(authenticationProvider);
    }


  }

}
