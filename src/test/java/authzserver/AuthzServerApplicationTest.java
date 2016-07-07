package authzserver;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.sql.DataSource;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;

import static authzserver.shibboleth.ShibbolethPreAuthenticatedProcessingFilter.*;
import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = AuthzServerApplication.class)
@WebAppConfiguration
@IntegrationTest("server.port:0")
public class AuthzServerApplicationTest {

  @Value("${local.server.port}")
  private int port;

  private String callback = "http://localhost:8889/callback";

  @Autowired
  private DataSource dataSource;

  @Rule
  public WireMockRule wireMockRule = new WireMockRule(8889);

  // we need both flavours for following redirect and looking into non-200 return codes
  private RestTemplate restTemplate = new RestTemplate();
  private RestTemplate testRestTemplate = new TestRestTemplate();


  @Before
  public void before() {
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    jdbcTemplate.execute("DELETE FROM `oauth_client_details` where `client_id` = 'test_client' or `client_id` = 'test_resource_server'");
    String insertTestClientSql = "INSERT INTO `oauth_client_details` (`client_id`, `resource_ids`, `client_secret`, `scope`, `authorized_grant_types`, `web_server_redirect_uri`, `authorities`, `access_token_validity`, `refresh_token_validity`, `additional_information`, `autoapprove`)" +
      " VALUES " +
      "('test_client', NULL, '$2a$10$zIvukHqZA7nfaZTNNP2i/e8tX/TdlwMkQSq9uq7FHZrcRJgPIUFUC', 'read,write', 'client_credentials,authorization_code', NULL, 'ROLE_TOKEN_CHECKER', NULL, NULL, NULL, 'true')";
    String insertTestResourceServerSql = "INSERT INTO `oauth_client_details` (`client_id`, `resource_ids`, `client_secret`, `scope`, `authorized_grant_types`, `web_server_redirect_uri`, `authorities`, `access_token_validity`, `refresh_token_validity`, `additional_information`, `autoapprove`)" +
      " VALUES " +
      "('test_resource_server', NULL, '$2a$10$zIvukHqZA7nfaZTNNP2i/e8tX/TdlwMkQSq9uq7FHZrcRJgPIUFUC', 'read,write', 'none', NULL, 'ROLE_TOKEN_CHECKER', NULL, NULL, NULL, 'true')";
    jdbcTemplate.execute(insertTestClientSql);
    jdbcTemplate.execute(insertTestResourceServerSql);
  }

  @Test
  public void test_skip_confirmation_autoapprove_true() throws InterruptedException {
    String serverUrl = "http://localhost:" + this.port;

    HttpHeaders headers = getShibHttpHeaders();

    wireMockRule.stubFor(get(urlMatching("/callback.*")).withQueryParam("code", matching(".*")).willReturn(aResponse().withStatus(200)));

    ResponseEntity<String> response = restTemplate.exchange(serverUrl + "/oauth/authorize?response_type=code&client_id=test_client&scope=read&redirect_uri={callback}", HttpMethod.GET, new HttpEntity<>(headers), String.class, callback);
    assertEquals(200, response.getStatusCode().value());

    List<LoggedRequest> requests = findAll(getRequestedFor(urlMatching("/callback.*")));
    assertEquals(1, requests.size());

    String authorizationCode = requests.get(0).queryParameter("code").firstValue();

    addAuthorizationHeaders(headers);

    MultiValueMap<String, String> bodyMap = getAuthorizationCodeFormParameters(authorizationCode);

    Map body = restTemplate.exchange(serverUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<>(bodyMap, headers), Map.class).getBody();
    assertEquals("bearer", body.get("token_type"));
    String accessToken = (String) body.get("access_token");
    assertNotNull(accessToken);

    // Now for the completeness of the scenario retrieve the Principal (e.g. impersonating a Resource Server) using the accessCode
    MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
    formData.add("token", accessToken);
    Map principal = restTemplate.exchange(serverUrl + "/oauth/check_token", HttpMethod.POST, new HttpEntity<>(formData, headers), Map.class).getBody();
    assertEquals("urn:collab:person:example.com:mock-user", principal.get("user_name"));
    assertEquals("admin@example.com", principal.get("email"));
    assertEquals("admin@example.com", principal.get("eduPersonPrincipalName"));
    assertEquals("John Doe", principal.get("displayName"));
  }

  @Test
  public void testErrorPage() {
    String url = "http://localhost:" + this.port + "/bogus";
    Map map = testRestTemplate.getForObject(url, Map.class);

    assertEquals(500, map.get("status"));

    HttpHeaders headers = getShibHttpHeaders();
    ResponseEntity<Map> response = testRestTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), Map.class);

    assertEquals(404, response.getBody().get("status"));
  }

  @Test
  public void testOpenRedirectResourceServer() throws Exception {
    HttpHeaders headers = getShibHttpHeaders();
    String serverUrl = "http://localhost:" + this.port + "/oauth/authorize?response_type=code&client_id=test_resource_server&scope=read&redirect_uri=https://google.com";

    ResponseEntity<String> response = testRestTemplate.exchange(serverUrl, HttpMethod.GET, new HttpEntity<>(headers), String.class, callback);
    assertEquals(400, response.getStatusCode().value());
    String body = response.getBody();

    assertTrue(body.contains("A redirect_uri can only be used by implicit or authorization_code grant types"));
  }

  private MultiValueMap<String, String> getAuthorizationCodeFormParameters(String authorizationCode) {
    MultiValueMap<String, String> bodyMap = new LinkedMultiValueMap<>();
    bodyMap.add("grant_type", "authorization_code");
    bodyMap.add("code", authorizationCode);
    bodyMap.add("redirect_uri", callback);
    return bodyMap;
  }

  private void addAuthorizationHeaders(HttpHeaders headers) {
    String authenticationCredentials = "Basic " + new String(Base64.encodeBase64(new String("test_client" + ":" + "secret").getBytes(Charset.forName("UTF-8"))));
    headers.add("Authorization", authenticationCredentials);
    headers.add("Content-Type", "application/x-www-form-urlencoded");
    headers.add("Accept", "application/json");
  }

  private HttpHeaders getShibHttpHeaders() {
    HttpHeaders headers = new HttpHeaders();
    headers.add(SHIB_NAME_ID_HEADER_NAME, "urn:collab:person:example.com:mock-user");
    headers.add(SHIB_AUTHENTICATING_AUTHORITY, "my-university");
    headers.add(SHIB_SCHAC_HOME_ORGANIZATION_HEADER_NAME, "example.com");
    headers.add(SHIB_EMAIL, "admin@example.com");
    headers.add(SHIB_EDU_PERSON_PRINCIPAL_NAME, "admin@example.com");
    headers.add(SHIB_DISPLAY_NAME, "John Doe");
    return headers;
  }


}

