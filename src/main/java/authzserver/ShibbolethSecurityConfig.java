package authzserver;

import authzserver.mock.MockShibbolethFilter;
import authzserver.shibboleth.ShibbolethPreAuthenticatedProcessingFilter;
import authzserver.shibboleth.ShibbolethUserDetailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;

@Configuration
@EnableWebSecurity
public class ShibbolethSecurityConfig extends WebSecurityConfigurerAdapter {

  private static final Logger LOG = LoggerFactory.getLogger(ShibbolethSecurityConfig.class);

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

    //we want to specify the exact order and RegistrationBean#setOrder does not support pinpointing the order before class
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
