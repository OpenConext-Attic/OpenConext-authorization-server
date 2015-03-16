package authzserver;

import junit.framework.TestCase;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.*;

public class CorsFilterTest extends TestCase {

  private CorsFilter subject = new CorsFilter();

  @Test
  public void testDoFilterWithNoPreFlight() throws Exception {
    HttpServletRequest req = new MockHttpServletRequest();
    HttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    subject.doFilter(req, res, chain);

    verify(chain, atLeastOnce()).doFilter(req, res);

    assertDefaultCorsHeaders(res);

    assertNull(res.getHeader("Access-Control-Allow-Headers"));
  }

  private void assertDefaultCorsHeaders(HttpServletResponse res) {
    assertEquals("*", res.getHeader("Access-Control-Allow-Origin"));
    assertEquals("*", res.getHeader("Access-Control-Allow-Methods"));
    assertEquals("true", res.getHeader("Access-Control-Allow-Credentials"));
    assertEquals("1728000", res.getHeader("Access-Control-Max-Age"));
  }

  @Test
  public void testDoFilterWithPreFlight() throws Exception {
    MockHttpServletRequest req = new MockHttpServletRequest("OPTIONS", "http://localhost");
    HttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);
    req.addHeader("Access-Control-Request-Method", "POST");
    String requestedRequestHeader = "Requested Request Headers";
    req.addHeader("Access-Control-Request-Headers", requestedRequestHeader);

    subject.doFilter(req, res, chain);

    verify(chain, never()).doFilter(req, res);

    assertDefaultCorsHeaders(res);

    assertEquals(requestedRequestHeader, res.getHeader("Access-Control-Allow-Headers"));
  }

}
