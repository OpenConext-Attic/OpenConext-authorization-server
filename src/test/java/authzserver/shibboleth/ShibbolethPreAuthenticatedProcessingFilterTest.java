package authzserver.shibboleth;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;

import static authzserver.shibboleth.ShibbolethPreAuthenticatedProcessingFilter.*;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

public class ShibbolethPreAuthenticatedProcessingFilterTest {

  private ShibbolethPreAuthenticatedProcessingFilter subject;

  @Before
  public void before() throws Exception {
    AuthenticationManager authenticationMananger = mock(AuthenticationManager.class);
    this.subject = new ShibbolethPreAuthenticatedProcessingFilter(authenticationMananger);
  }

  @Test
  public void testGetPreAuthenticatedPrincipal() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader(COLLAB_PERSON_ID_HEADER_NAME, "urn:collab:person:admin");
    request.addHeader(SCHAC_HOME_ORGANIZATION_HEADER_NAME, "schac");
    request.addHeader(SHIB_AUTHENTICATING_AUTHORITY, "http://mock-idp;http://mock-idp");

    ShibbolethUser user = (ShibbolethUser) this.subject.getPreAuthenticatedPrincipal(request);

    assertEquals(user.getAuthenticatingAuthority(), "http://mock-idp");
  }

  @Test(expected = PreAuthenticatedCredentialsNotFoundException.class)
  public void testGetPreAuthenticatedPrincipalRequiredHeaderPersonId() throws Exception {
    this.subject.getPreAuthenticatedPrincipal(new MockHttpServletRequest());
  }

  @Test(expected = PreAuthenticatedCredentialsNotFoundException.class)
  public void testGetPreAuthenticatedPrincipalRequiredHeaderSchac() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader(COLLAB_PERSON_ID_HEADER_NAME, "urn:collab:person:admin");
    this.subject.getPreAuthenticatedPrincipal(request);
  }

  @Test(expected = PreAuthenticatedCredentialsNotFoundException.class)
  public void testGetPreAuthenticatedPrincipalRequiredHeaderAuthenticatingAuthority() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader(COLLAB_PERSON_ID_HEADER_NAME, "urn:collab:person:admin");
    request.addHeader(SCHAC_HOME_ORGANIZATION_HEADER_NAME, "schac");
    this.subject.getPreAuthenticatedPrincipal(request);
  }
}
