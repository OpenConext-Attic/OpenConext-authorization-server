package authzserver;

import authzserver.AuthzServerApplication.Oauth2ServerConfig;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.ConfigFileApplicationContextInitializer;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {AuthzServerApplication.class, Oauth2ServerConfig.class}, initializers = ConfigFileApplicationContextInitializer.class)
@WebAppConfiguration
@IntegrationTest("server.port:0")
@DirtiesContext
@ActiveProfiles("dev")
public class AuthzServerApplicationTest {
  @Value("${local.server.port}")
  private int port;

  @Test
  public void testItBoots() throws Exception {
    assertTrue("It boots", true);

  }
}
