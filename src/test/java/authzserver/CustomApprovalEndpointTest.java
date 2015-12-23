package authzserver;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = AuthzServerApplication.class)
@WebIntegrationTest(randomPort = true, value = {"spring.profiles.active=dev"})
public class CustomApprovalEndpointTest {

  @Value("${local.server.port}")
  private int port;

  private TestRestTemplate template = new TestRestTemplate();

  @Test
  public void testGetAccessConfirmation() throws Exception {
    String result = template.getForObject("http://localhost:" + this.port + "/oauth/confirm", String.class);

    assertTrue(result.contains("<input type=\"hidden\" value=\"true\" id=\"scope.groupsallow\" name=\"scope.groups\" />"));
    assertTrue(result.contains("client_id"));
  }
}
