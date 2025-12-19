package singpass.demo;

public final class Constants {
  private Constants() {
  }

  public static final String SESSION_COOKIE_NAME = "sessionId";

  public static final String CONFIG_PATH = "../config.json";
  public static final String FRONTEND_DIRECTORY = "../frontend";

  // This is used to set the expiry time for the DPoP and client assertion JWTs
  // Singpass requires that this must be less than 120 seconds
  public static final int JWT_EXPIRY_SECONDS = 60;

  public static final String CONTENT_TYPE_HTML = "text/html";
  public static final String CONTENT_TYPE_CSS = "text/css";
  public static final String CONTENT_TYPE_SVG = "image/svg+xml";
  public static final String CONTENT_TYPE_PLAIN_TEXT = "text/plain";
  public static final String CONTENT_TYPE_JSON = "application/json";

  public static final String DPOP_JWT_TYPE = "dpop+jwt";
}
