package authzserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.MetricFilterAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.TraceWebFilterAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

import javax.sql.DataSource;
import java.util.Locale;

@SpringBootApplication(exclude = {TraceWebFilterAutoConfiguration.class, MetricFilterAutoConfiguration.class})
public class AuthzServerApplication {

  public static void main(String[] args) {
    SpringApplication.run(AuthzServerApplication.class, args);
  }

  public static final String ROLE_TOKEN_CHECKER = "ROLE_TOKEN_CHECKER";

  @Configuration
  @EnableAuthorizationServer
  protected static class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private ApprovalStoreUserApprovalHandler approvalStoreUserApprovalHandler;

    @Value("${oauthServer.accessTokenValiditySeconds}")
    private Integer accessTokenValiditySeconds;

    @Value("${oauthServer.refreshTokenValiditySeconds}")
    private Integer refreshTokenValiditySeconds;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints)
      throws Exception {
      final DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
      accessTokenConverter.setUserTokenConverter(new SchacHomeAwareUserAuthenticationConverter());

      endpoints
        .pathMapping("/oauth/confirm_access", "/oauth/confirm")
        .userApprovalHandler(approvalStoreUserApprovalHandler)
        .accessTokenConverter(accessTokenConverter)
        .tokenServices(tokenServices())
        .authorizationCodeServices(new JdbcAuthorizationCodeServices(this.dataSource));
    }

    @Bean
    @Autowired
    public ApprovalStoreUserApprovalHandler approvalStoreUserApprovalHandler(
      @Value("${oauthServer.approvalExpirySeconds}") Integer approvalExpirySeconds,
      ApprovalStore approvalStore, ClientDetailsService clientDetailsService) {
      final ApprovalStoreUserApprovalHandler userApprovalHandler = new ApprovalStoreUserApprovalHandler();
      userApprovalHandler.setApprovalExpiryInSeconds(approvalExpirySeconds);
      userApprovalHandler.setApprovalStore(approvalStore);
      userApprovalHandler.setClientDetailsService(clientDetailsService);

      DefaultOAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
      userApprovalHandler.setRequestFactory(requestFactory);
      return userApprovalHandler;
    }

    @Bean
    public ApprovalStore approvalStore() {
      return new JdbcApprovalStore(dataSource);
    }


    @Bean
    public ConcurrentJdbcTokenStore tokenStore() {
      return new ConcurrentJdbcTokenStore(dataSource);
    }

    private DefaultTokenServices tokenServices() {
      final DefaultTokenServices tokenServices = new DefaultTokenServices();
      tokenServices.setSupportRefreshToken(true);
      tokenServices.setTokenStore(tokenStore());
      tokenServices.setAccessTokenValiditySeconds(accessTokenValiditySeconds);
      tokenServices.setRefreshTokenValiditySeconds(refreshTokenValiditySeconds);
      return tokenServices;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
      oauthServer
        .checkTokenAccess("hasAuthority('" + ROLE_TOKEN_CHECKER + "')")
        .passwordEncoder(passwordEncoder());
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer configurer) throws Exception {
      configurer.jdbc(dataSource);
    }
  }

  @Bean
  public FilterRegistrationBean lenientCorsFilter() {
    FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
    filterRegistrationBean.setFilter(new CorsFilter());
    return filterRegistrationBean;
  }

  @Bean
  public LocaleResolver localeResolver() {
    CookieLocaleResolver slr = new CookieLocaleResolver();
    slr.setDefaultLocale(Locale.ENGLISH);
    return slr;
  }

  @Bean
  public LocaleChangeInterceptor localeChangeInterceptor() {
    LocaleChangeInterceptor lci = new LocaleChangeInterceptor();
    lci.setParamName("lang");
    return lci;
  }

  @Bean
  public WebMvcConfigurerAdapter adapter() {
    return new WebMvcConfigurerAdapter() {
      @Override
      public void addInterceptors(InterceptorRegistry registry) {
        super.addInterceptors(registry);
        registry.addInterceptor(localeChangeInterceptor());
      }
    };
  }


}
