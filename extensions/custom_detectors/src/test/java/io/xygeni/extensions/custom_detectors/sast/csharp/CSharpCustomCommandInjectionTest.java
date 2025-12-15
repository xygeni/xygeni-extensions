package io.xygeni.extensions.custom_detectors.sast.csharp;

import io.xygeni.extensions.custom_detectors.sast.test.assertions.SastAssertions;
import org.junit.jupiter.api.Test;

import java.io.File;

import static io.xygeni.extensions.custom_detectors.sast.csharp.CSharpTestHelper.CSHARP_DIR;
import static io.xygeni.extensions.custom_detectors.sast.csharp.CSharpTestHelper.runCSharp;
import static io.xygeni.extensions.custom_detectors.sast.test.helpers.SastDetectorTestHelper.dump;

/**
 * CSharpCustomCommandInjectionTest - Unit tests for custom_command_injection detector.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class CSharpCustomCommandInjectionTest {
  private static final String ID = "custom_command_injection";
  private static final File DETECTOR_DIR = new File(CSHARP_DIR, ID);

  @Test
  public void testRegression() {
    var file = new File(DETECTOR_DIR, "regression");
    var ctx = runCSharp(file, ID);
    dump(ctx);
    SastAssertions.assertThat(ctx).matchesIssues();
  }
}
