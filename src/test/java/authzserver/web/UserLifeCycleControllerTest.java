package authzserver.web;

import authzserver.AbstractIntegrationTest;
import authzserver.model.Attribute;
import authzserver.model.LifeCycleResult;
import org.junit.Test;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

import static io.restassured.RestAssured.given;
import static java.util.stream.Collectors.toList;
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
    LifeCycleResult expected = getExpectedLifeCycleResult();

    assertEquals(expected, result);
  }

  @Test
  public void dryRun() {
    LifeCycleResult result = doDeprovision(true);
    LifeCycleResult expected = getExpectedLifeCycleResult();

    assertEquals(expected, result);
  }

  @Test
  public void deprovision() {
    LifeCycleResult result = doDeprovision(false);
    LifeCycleResult expected = getExpectedLifeCycleResult();

    assertEquals(expected, result);

    result = doDeprovision(false);
    expected = new LifeCycleResult();

    assertEquals(expected, result);
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

  private LifeCycleResult getExpectedLifeCycleResult() {
    LifeCycleResult expected = new LifeCycleResult();

    List<Attribute> attributes = Arrays.asList(
      new Attribute("approval", "test_client_read_APPROVED"),
      new Attribute("authenticating_authority", "my-university"),
      new Attribute("edu_person_principal_name", "admin@example.com"),
      new Attribute("display_name", "John Doe"),
      new Attribute("schac_home_organisation", "example.com"),
      new Attribute("email", "admin@example.com"),
      new Attribute("user_name", "urn:collab:person:example.com:mock-user"))
      .stream()
      .sorted(Comparator.comparing(Attribute::getName))
      .collect(toList());
    expected.setData(attributes);
    return expected;
  }
}
