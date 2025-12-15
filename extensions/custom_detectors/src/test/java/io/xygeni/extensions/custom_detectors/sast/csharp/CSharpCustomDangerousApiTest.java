package io.xygeni.extensions.custom_detectors.sast.csharp;

import io.xygeni.extensions.custom_detectors.sast.test.assertions.SastAssertions;
import org.junit.jupiter.api.Test;

import static io.xygeni.extensions.custom_detectors.sast.csharp.CSharpTestHelper.runCSharp;
import static io.xygeni.extensions.custom_detectors.sast.test.helpers.SastDetectorTestHelper.dump;

/**
 * CSharpCustomDangerousApiTest - Unit tests for custom_dangerous_api detector.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class CSharpCustomDangerousApiTest {

  private static final String ID = "custom_dangerous_api";

  @Test
  public void testRegression() {
    var ctx = runCSharp(ID, "regression");
    dump(ctx);
    SastAssertions.assertThat(ctx).matchesIssues();
  }
}
