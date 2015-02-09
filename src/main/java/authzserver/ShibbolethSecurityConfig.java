package authzserver;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class ShibbolethSecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication().withUser("marissa").password("wombat").roles("USER").and().withUser("sam")
      .password("kangaroo").roles("USER");
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    web.
      ignoring().antMatchers("/resources/**", "/static/**");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    // shibboleth stuff will be here
  }

}

