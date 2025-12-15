package io.xygeni.extensions.custom_detectors.sast.python;

import io.xygeni.extensions.custom_detectors.sast.test.assertions.SastAssertions;
import io.xygeni.sast.scanner.config.SastRuleConfig;
import io.xygeni.sast.scanner.engine.SastContext;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.function.Consumer;

import static io.xygeni.extensions.custom_detectors.sast.test.helpers.SastDetectorTestHelper.SAST_DETECTORS_TEST_DIR;
import static io.xygeni.extensions.custom_detectors.sast.test.helpers.SastDetectorTestHelper.run;
import static io.xygeni.extensions.custom_detectors.sast.test.helpers.SastDetectorTestHelper.runOnDir;

/**
 * PythonTestHelper - Helper for unit testing Python SAST detectors.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class PythonTestHelper {

  public static final File PYTHON_DIR = new File(SAST_DETECTORS_TEST_DIR, "python");

  public static File testResource(String name) {
    return new File(PYTHON_DIR, name);
  }

  public static SastContext runPython(String detectorId, String resource) {
    var dir = testResource(detectorId);
    var resourceDir = new File(dir, resource);
    return runPython(resourceDir, detectorId);
  }

  public static SastContext runPython(File dir, String detectorId) {
    var qualifiedDetectorId = qualifyDetectorId(detectorId);
    return runOnDir(
      dir,
      File::isFile,
      qualifiedDetectorId
    );
  }

  public static SastContext runPython(String detectorId, String resource, Consumer<SastRuleConfig> changeConfig) {
    var dir = testResource(detectorId);
    var resourceDir = new File(dir, resource);
    var qualifiedDetectorId = qualifyDetectorId(detectorId);
    return run(
      resourceDir,
      File::isFile,
      qualifiedDetectorId,
      changeConfig
    );
  }

  public static SastContext runPython(File dir, String detectorId, Consumer<SastRuleConfig> changeConfig) {
    var qualifiedDetectorId = qualifyDetectorId(detectorId);
    return run(
      dir,
      File::isFile,
      qualifiedDetectorId,
      changeConfig
    );
  }

  public static SastContext runAndAssertPython(String detectorId, String resource) {
    var ctx = runPython(detectorId, resource);
    SastAssertions.assertThat(ctx).matchesIssues();

    return ctx;
  }

  public static SastContext runAndAssertPython(File dir, String detectorId) {
    var qualifiedDetectorId = qualifyDetectorId(detectorId);
    var ctx = runPython(dir, qualifiedDetectorId);
    SastAssertions.assertThat(ctx).matchesIssues();

    return ctx;
  }

  public static SastContext runAndAssertPython(String detectorId, String resource, Consumer<SastRuleConfig> changeConfig) {
    var ctx = runPython(detectorId, resource, changeConfig);
    SastAssertions.assertThat(ctx).matchesIssues();

    return ctx;
  }

  public static SastContext runAndAssertPython(File dir, String detectorId, Consumer<SastRuleConfig> changeConfig) {
    var qualifiedDetectorId = qualifyDetectorId(detectorId);
    var ctx = runPython(dir, qualifiedDetectorId, changeConfig);
    SastAssertions.assertThat(ctx).matchesIssues();

    return ctx;
  }

  @Nonnull
  private static String qualifyDetectorId(String detectorId) {
    return detectorId.startsWith("python.") ? detectorId : "python." + detectorId;
  }
}
