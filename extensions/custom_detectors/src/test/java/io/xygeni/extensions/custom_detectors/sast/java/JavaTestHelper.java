package io.xygeni.extensions.custom_detectors.sast.java;

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
 * JavaTestHelper - Helper for unit testing Java SAST detectors.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class JavaTestHelper {

  public static final File JAVA_DIR = new File(SAST_DETECTORS_TEST_DIR, "java");

  public static File testResource(String name) {
    return new File(JAVA_DIR, name);
  }

  public static SastContext runJava(String detectorId, String resource) {
    var dir = testResource(detectorId);
    var resourceDir = new File(dir, resource);
    return runJava(resourceDir, detectorId);
  }

  public static SastContext runJava(File dir, String detectorId) {
    var qualifiedDetectorId = qualifyDetectorId(detectorId);
    return runOnDir(
      dir,
      File::isFile,
      qualifiedDetectorId
    );
  }

  public static SastContext runJava(String detectorId, String resource, Consumer<SastRuleConfig> changeConfig) {
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

  public static SastContext runJava(File dir, String detectorId, Consumer<SastRuleConfig> changeConfig) {
    var qualifiedDetectorId = qualifyDetectorId(detectorId);
    return run(
      dir,
      File::isFile,
      qualifiedDetectorId,
      changeConfig
    );
  }

  public static SastContext runAndAssertJava(String detectorId, String resource) {
    var ctx = runJava(detectorId, resource);
    SastAssertions.assertThat(ctx).matchesIssues();

    return ctx;
  }

  public static SastContext runAndAssertJava(File dir, String detectorId) {
    var qualifiedDetectorId = qualifyDetectorId(detectorId);
    var ctx = runJava(dir, qualifiedDetectorId);
    SastAssertions.assertThat(ctx).matchesIssues();

    return ctx;
  }

  public static SastContext runAndAssertJava(String detectorId, String resource, Consumer<SastRuleConfig> changeConfig) {
    var ctx = runJava(detectorId, resource, changeConfig);
    SastAssertions.assertThat(ctx).matchesIssues();

    return ctx;
  }

  public static SastContext runAndAssertJava(File dir, String detectorId, Consumer<SastRuleConfig> changeConfig) {
    var qualifiedDetectorId = qualifyDetectorId(detectorId);
    var ctx = runJava(dir, qualifiedDetectorId, changeConfig);
    SastAssertions.assertThat(ctx).matchesIssues();

    return ctx;
  }

  @Nonnull
  private static String qualifyDetectorId(String detectorId) {
    return detectorId.startsWith("java.") ? detectorId : "java." + detectorId;
  }
}
