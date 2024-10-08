package io.xygeni.extensions.custom_detectors.secrets.verifier;

import com.depsdoctor.commons.TriState;
import com.depsdoctor.commons.os.OS;
import org.assertj.core.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

//@ExtendWith(SoftAssertionsExtension.class)
class XygeniJwtVerifierTest {
  private static final String VAR_XYGENI_TEST_TOKEN = "XYGENI_TEST_TOKEN";
  private static final String revoked = "xya_eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJsdWlzLnJvZHJpZ3VleitpbkB4eWdlbmkuaW8iLCJpYXQiOjE3MjgzMTc0NjYsImV4cCI6MTcyODkyMjI2NiwiYXBpdG9rZW5kYXRhIjp7InVzZXJCZWFuIjp7ImlkIjo4MjcsIm5hbWUiOiJMdWlzIFJvZHJpZ3VleiBCZXJ6b3NhIiwibG9naW4iOiJsdWlzLnJvZHJpZ3VleitpbkB4eWdlbmkuaW8iLCJjdXN0b21lcklkIjo0MywibWZhIjpmYWxzZSwibWZhQWxsIjpmYWxzZSwiYXV0aG9yaXRpZXMiOlt7ImF1dGhvcml0eSI6IlJPTEVfUk9PVCJ9XSwiZW5hYmxlZCI6ZmFsc2UsImNoYW5nZWRQYXNzd29yZCI6ZmFsc2UsImN1c3RvbWVyT3duZXIiOnRydWUsImFjY291bnROb25FeHBpcmVkIjp0cnVlLCJhY2NvdW50Tm9uTG9ja2VkIjp0cnVlLCJjcmVkZW50aWFsc05vbkV4cGlyZWQiOnRydWUsIm1mYUVuYWJsZWQiOmZhbHNlLCJzdGFydFN1YnNjcmlwdGlvbiI6MTcxNTE2NzI0NzAwMCwiZW5kU3Vic2NyaXB0aW9uIjoxNzQ2MDk4NDQ3MDAwLCJwbGF0Zm9ybSI6IlhZR0VOSSIsInVzZXJDdXN0b21lcklkIjo4NCwiY3VzdG9tZXJFbWFpbCI6Imx1aXMucm9kcmlndWV6K2luQHh5Z2VuaS5pbyIsInByb2plY3RJZHMiOltdLCJmZWF0dXJlcyI6W10sImVhcmx5QWNjZXNzIjpmYWxzZSwidXNlcm5hbWUiOiJsdWlzLnJvZHJpZ3VleitpbkB4eWdlbmkuaW8ifSwidG9rZW5JZCI6MTE3NjV9fQ.vUrK9nAuVDXKz5Llh--NiIU0LMGggy52ITyYTbwdoXNncRSRTKAZ5cspynU4n_iGKudR2jitR_47wA-nR-lD6w";

  @Test @DisplayName("verify(revoked token) must be FALSE")
  void verify_revoked() {
    var verifier = new XygeniJwtVerifier();
    TriState result = verifier.verify(revoked);
    assertThat(result).isEqualTo(TriState.FALSE);
  }

  @Test @DisplayName("verify(valid token) must be TRUE")
  void verify_valid() {
    // Assume that the token is passed via environment variable "XYGENI_TEST_TOKEN" (never hard-code secrets ;)
    String token = OS.getProperty(VAR_XYGENI_TEST_TOKEN, "");
    Assumptions.assumeThat(token).isNotBlank();

    var verifier = new XygeniJwtVerifier();
    TriState result = verifier.verify(token);
    assertThat(result).isEqualTo(TriState.TRUE);
  }

}