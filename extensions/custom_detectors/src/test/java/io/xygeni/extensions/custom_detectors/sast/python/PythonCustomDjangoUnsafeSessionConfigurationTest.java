package io.xygeni.extensions.custom_detectors.sast.python;

import io.xygeni.extensions.custom_detectors.sast.test.assertions.SastAssertions;
import org.junit.jupiter.api.Test;

import static io.xygeni.extensions.custom_detectors.sast.python.PythonTestHelper.runPython;
import static io.xygeni.extensions.custom_detectors.sast.test.helpers.SastDetectorTestHelper.dump;

/**
 * PythonCustomDjangoUnsafeSessionConfigurationTest - Unit tests for
 * custom_django_unsafe_session_configuration detector.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class PythonCustomDjangoUnsafeSessionConfigurationTest {

  private static final String ID = "custom_django_unsafe_session_configuration";

  @Test
  public void testUnsafe() {
    var ctx = runPython(ID, "unsafe");
    dump(ctx);
    //SastAssertions.assertThat(ctx).matchesIssues();
  }
}
