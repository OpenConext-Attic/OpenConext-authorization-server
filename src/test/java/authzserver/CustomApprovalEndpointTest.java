package authzserver;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.assertTrue;

@ActiveProfiles("dev")
public class CustomApprovalEndpointTest extends AbstractIntegrationTest{

  @Test
  public void testGetAccessConfirmation() throws Exception {
    String result = restTemplate.getForObject("http://localhost:" + this.port + "/oauth/confirm", String.class);

    assertTrue(result.contains("<input type=\"hidden\" value=\"true\" id=\"scope.groupsallow\" name=\"scope.groups\" />"));
    assertTrue(result.contains("client_id"));
  }
}
