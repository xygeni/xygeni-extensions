package io.xygeni.extensions.custom_detectors.secrets;

import com.depsdoctor.core.utils.jwt.JWT;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link XygeniJwtDetector}. It is recommended to cover each custom detector in its own unit test case.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
class XygeniJwtDetectorTest {
  // These tokens are expired but with the real structure needed for this detector
  private static final String EXPIRED_JWT =
    "eyJhbGciOiJIUzUxMiJ9."+
    "eyJzdWIiOiJ4QG15b3JnLmlvIiwiaWF0IjoxNjgwMTExMTIwLCJleHAiOjE2ODI4ODcxMj"+
    "AsImFwaXRva2VuZGF0YSI6eyJ1c2VyQmVhbiI6eyJpZCI6NDEsIm5hbWUiOiJVc2VyIiwi"+
    "bG9naW4iOiJ4QG15b3JnLmlvIiwiY3VzdG9tZXJJZCI6MSwiYXV0aG9yaXRpZXMiOlt7Im"+
    "F1dGhvcml0eSI6IlVTRVIifV0sImVuYWJsZWQiOmZhbHNlLCJjaGFuZ2VkUGFzc3dvcmQi"+
    "OmZhbHNlLCJjdXN0b21lck93bmVyIjpmYWxzZSwiYWNjb3VudE5vbkV4cGlyZWQiOnRydW"+
    "UsImFjY291bnROb25Mb2NrZWQiOnRydWUsImNyZWRlbnRpYWxzTm9uRXhwaXJlZCI6dHJ1"+
    "ZSwicHJvamVjdElkcyI6WzcsMTFdLCJ1c2VybmFtZSI6InhAbXlvcmcuaW8ifSwidG9rZW"+
    "5JZCI6MzYyN319."+
    "LmAZ29sLnOfN3KjiT6ol2xLRl5rrr-lBucDskbWQq8qdrnhwPyeZcyk5OOnNlJYhZmqVloTvkdQ9n4CA8htcBg";

  private static final String ZOOM_TOKEN =
    "eyJhbGciOiJIUzUxMiIsInYiOiIyLjAiLCJraWQiOiI8S0lEPiJ9."+
    "eyJ2ZXIiOiI2IiwiY2xpZW50SWQiOiI8Q2xpZW50X0lEPiIsImNvZGUiOiI8Q29kZT4iLCJpc3MiOiJ1cm46em9vbTpjb25uZWN0Om"+
    "NsaWVudGlkOjxDbGllbnRfSUQ-IiwiYXV0aGVudGljYXRpb25JZCI6IjxBdXRoZW50aWNhdGlvbl9JRD4iLCJ1c2VySWQiOiI8VXNl"+
    "cl9JRD4iLCJncm91cE51bWJlciI6MCwiYXVkIjoiaHR0cHM6Ly9vYXV0aC56b29tLnVzIiwiYWNjb3VudElkIjoiPEFjY291bnRfSUQ-"+
    "IiwibmJmIjoxNTgwMTQ2OTkzLCJleHAiOjE1ODAxNTA1OTMsInRva2VuVHlwZSI6ImFjY2Vzc190b2tlbiIsImlhdCI6MTU4MDE0Njk5"+
    "MywianRpIjoiPEpUST4iLCJ0b2xlcmFuY2VJZCI6MjV9."+
    "F9o_w7_lde4Jlmk_yspIlDc-6QGmVrCbe_6El-xrZehnMx7qyoZPUzyuNAKUKcHfbdZa6Q4QBSvpd6eIFXvjHw";

  @Test
  void test_real_xygeni_token() {
    JWT jwt = JWT.parse(EXPIRED_JWT);
    boolean isXygeni = new XygeniJwtDetector().isValidToken(jwt);
    assertThat(isXygeni).isTrue();
  }

  @Test void test_non_xygeni_token() {
    JWT jwt = JWT.parse(ZOOM_TOKEN);
    boolean isXygeni = new XygeniJwtDetector().isValidToken(jwt);
    assertThat(isXygeni).isFalse();
  }
}