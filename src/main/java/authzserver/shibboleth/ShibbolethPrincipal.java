package authzserver.shibboleth;

/**
 * Represents the data about the user that is provided to us by Shibboleth
 */
public class ShibbolethPrincipal {

  private final String uid;
  private final String displayName;

  public ShibbolethPrincipal(String uid, String displayName) {
    this.uid = uid;
    this.displayName = displayName;
  }

  public String getUid() {
    return uid;
  }

  public String getDisplayName() {
    return displayName;
  }


  @Override
  public String toString() {
    return "ShibbolethPrincipal{" +
      "uid='" + uid + '\'' +
      ", displayName='" + displayName + '\'' +
      '}';
  }
}
