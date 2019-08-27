package authzserver;


import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.nio.charset.Charset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;

import static java.util.stream.Collectors.toList;
import static org.junit.Assert.assertTrue;

public class TokenEndpointTest extends AbstractIntegrationTest {

  @Test
  public void concurrentClientCredentials() throws InterruptedException {
    HttpEntity<MultiValueMap<String, String>> request = getRequest();
    final int p = this.port;

    ExecutorService es = Executors.newFixedThreadPool(10);
    List<Callable<Boolean>> callables = IntStream.range(0, 20).mapToObj(i -> perform(request, p)).collect(toList());
    List<Future<Boolean>> futures = es.invokeAll(callables);
    futures.forEach(f -> {
      try {
        Boolean b = f.get();
        assertTrue(b);
      } catch (InterruptedException | ExecutionException e) {
        throw new IllegalArgumentException(e);
      }
    });

  }

  private Callable<Boolean> perform(HttpEntity<MultiValueMap<String, String>> request, int p) {
    return () -> {
      IntStream.range(0, 15).forEach(i -> {
        Object accessToken = restTemplate.postForEntity("http://localhost:" + p + "/oauth/token", request, Map.class).getBody().get("access_token");
        if (accessToken == null) {
          throw new IllegalArgumentException();
        }
      });
      return true;
    };
  }

  private HttpEntity<MultiValueMap<String, String>> getRequest() {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    headers.set("Authorization", "Basic " + new String(Base64.getEncoder().encode("test_client:secret".getBytes(Charset.defaultCharset()))));

    MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
    map.add("grant_type", "client_credentials");

    return new HttpEntity<>(map, headers);
  }

}
