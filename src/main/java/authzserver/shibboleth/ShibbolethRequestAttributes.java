package authzserver.shibboleth;

/**
 * Lists the names under which Shibboleth makes SAML attributes available on the HttpServletRequest
 */
public enum ShibbolethRequestAttributes {

  UID("shib_uid"), DISPLAY_NAME("shib_displayname");

  private final String attributeName;

  public String getAttributeName() {
    return attributeName;
  }

  ShibbolethRequestAttributes(String attributeName) {
    this.attributeName = attributeName;
  }
}
