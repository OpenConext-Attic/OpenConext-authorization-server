package authzserver;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.*;

public class CorsFilterTest {

  private CorsFilter subject = new CorsFilter();
  private MockHttpServletRequest req;
  private HttpServletResponse res;
  private FilterChain chain;


  @Before
  public void before() {
    req = new MockHttpServletRequest();
    res = new MockHttpServletResponse();
    chain = mock(FilterChain.class);
  }

  @Test
  public void testDoFilterWithNoPreFlight() throws Exception {
    subject.doFilter(req, res, chain);

    verify(chain, atLeastOnce()).doFilter(req, res);

    assertDefaultCorsHeaders(res);
    assertNull(res.getHeader("Access-Control-Allow-Headers"));
  }

  @Test
  public void testDoFilterWithPreFlight() throws Exception {
    String requestedRequestHeader = "Requested Request Headers";
    req.addHeader("Access-Control-Request-Method", "POST");
    req.addHeader("Access-Control-Request-Headers", requestedRequestHeader);
    req.setMethod("OPTIONS");

    subject.doFilter(req, res, chain);

    verify(chain, never()).doFilter(req, res);
    assertDefaultCorsHeaders(res);
    assertEquals(requestedRequestHeader, res.getHeader("Access-Control-Allow-Headers"));
  }

  private void assertDefaultCorsHeaders(HttpServletResponse res) {
    assertEquals("*", res.getHeader("Access-Control-Allow-Origin"));
    assertEquals("*", res.getHeader("Access-Control-Allow-Methods"));
    assertEquals("true", res.getHeader("Access-Control-Allow-Credentials"));
    assertEquals("1728000", res.getHeader("Access-Control-Max-Age"));
  }

}
