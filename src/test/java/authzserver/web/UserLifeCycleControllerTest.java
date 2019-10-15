package authzserver.web;

import authzserver.AbstractIntegrationTest;
import authzserver.model.LifeCycleResult;
import org.junit.Test;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static java.util.stream.Collectors.toMap;
import static org.junit.Assert.assertEquals;


public class UserLifeCycleControllerTest extends AbstractIntegrationTest {

  @Test
  public void preview() {
    LifeCycleResult result = given()
      .auth()
      .preemptive()
      .basic("user", "secret")
      .when()
      .get("deprovision/{user}", "urn:collab:person:example.com:mock-user")
      .as(LifeCycleResult.class);

    assertLifeCycleResult(result);
  }

  @Test
  public void dryRun() {
    LifeCycleResult result = doDeprovision(true);

    assertLifeCycleResult(result);
  }

  @Test
  public void deprovision() {
    LifeCycleResult result = doDeprovision(false);

    assertLifeCycleResult(result);
    result = doDeprovision(false);
    assertEquals(0, result.getData().size());
  }

  @Test
  public void unsupportedContentNegotion() {
    LifeCycleResult result = given()
      .auth()
      .preemptive()
      .basic("user", "secret")
      .when()
      .delete("deprovision/nope.me")
      .as(LifeCycleResult.class);
    assertEquals(0, result.getData().size());
  }

  private LifeCycleResult doDeprovision(boolean dryRun) {
    return given()
      .auth()
      .preemptive()
      .basic("user", "secret")
      .when()
      .delete("deprovision/{user}" + (dryRun ? "/dry-run" : ""), "urn:collab:person:example.com:mock-user")
      .as(LifeCycleResult.class);
  }


  private void assertLifeCycleResult(LifeCycleResult result) {
    Map<String, String> map = result.getData().stream().collect(toMap(attr -> attr.getName(), attr -> attr.getValue()));
    assertEquals(7, map.size());
    assertEquals(map.get("approval"), "test_client_read_APPROVED");
    assertEquals(map.get("authenticating_authority"), "my-university");
    assertEquals(map.get("edu_person_principal_name"), "admin@example.com");
    assertEquals(map.get("display_name"), "John Doe");
    assertEquals(map.get("schac_home_organisation"), "example.com");
    assertEquals(map.get("email"), "admin@example.com");
    assertEquals(map.get("user_name"), "urn:collab:person:example.com:mock-user");
  }

}
