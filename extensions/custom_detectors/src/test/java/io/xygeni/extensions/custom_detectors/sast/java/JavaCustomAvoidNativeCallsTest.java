package io.xygeni.extensions.custom_detectors.sast.java;

import io.xygeni.extensions.custom_detectors.sast.test.assertions.SastAssertions;
import org.junit.jupiter.api.Test;

import java.util.List;

import static io.xygeni.extensions.custom_detectors.sast.java.JavaTestHelper.runAndAssertJava;
import static io.xygeni.extensions.custom_detectors.sast.java.JavaTestHelper.runJava;
import static io.xygeni.extensions.custom_detectors.sast.test.helpers.SastDetectorTestHelper.dump;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * JavaCustomAvoidNativeCallsTest - Unit tests for custom_avoid_native_calls detector.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
class JavaCustomAvoidNativeCallsTest {

  private static final String ID = "custom_avoid_native_calls";

  @Test
  public void testRegression() {
    var ctx = runJava(ID, "regression");
    dump(ctx);
    SastAssertions.assertThat(ctx).matchesIssues();
  }

  @Test
  public void testAllowedMethods() {
    var ctx = runJava(
        ID, "regression", conf -> {
          conf.addProperty("allowedMethods", List.of("com.reg.nat.CustomAvoidNativeCalls.print"));
        }
    );

    assertThat(ctx.codeVulnerabilities()).isEmpty();
  }
}
