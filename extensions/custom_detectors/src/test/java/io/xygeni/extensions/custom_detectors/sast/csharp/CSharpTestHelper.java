package io.xygeni.extensions.custom_detectors.sast.csharp;

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
 * CSharpTestHelper - Helper for unit testing C# SAST detectors.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class CSharpTestHelper {

  public static final File CSHARP_DIR = new File(SAST_DETECTORS_TEST_DIR, "csharp");

  public static File testResource(String name) {
    return new File(CSHARP_DIR, name);
  }

  public static SastContext runCSharp(String detectorId, String resource) {
    var dir = testResource(detectorId);
    var resourceDir = new File(dir, resource);
    return runCSharp(resourceDir, detectorId);
  }

  public static SastContext runCSharp(File dir, String detectorId) {
    var qualifiedDetectorId = qualifyDetectorId(detectorId);
    return runOnDir(
      dir,
      File::isFile,
      qualifiedDetectorId
    );
  }

  public static SastContext runCSharp(String detectorId, String resource, Consumer<SastRuleConfig> changeConfig) {
    var dir = testResource(detectorId);
    var resourceDir = new File(dir, resource);
    var qualifiedDetectorId = qualifyDetectorId(detectorId);
    return run( resourceDir, File::isFile, qualifiedDetectorId, changeConfig );
  }

  public static SastContext runCSharp(File dir, String detectorId, Consumer<SastRuleConfig> changeConfig) {
    var qualifiedDetectorId = qualifyDetectorId(detectorId);
    return run( dir, File::isFile, qualifiedDetectorId, changeConfig );
  }

  public static SastContext runAndAssertCSharp(String detectorId, String resource) {
    var ctx = runCSharp(detectorId, resource);
    SastAssertions.assertThat(ctx).matchesIssues();

    return ctx;
  }

  public static SastContext runAndAssertCSharp(File dir, String detectorId) {
    var qualifiedDetectorId = qualifyDetectorId(detectorId);
    var ctx = runCSharp(dir, qualifiedDetectorId);
    SastAssertions.assertThat(ctx).matchesIssues();

    return ctx;
  }

  public static SastContext runAndAssertCSharp(String detectorId, String resource, Consumer<SastRuleConfig> changeConfig) {
    var ctx = runCSharp(detectorId, resource, changeConfig);
    SastAssertions.assertThat(ctx).matchesIssues();

    return ctx;
  }

  public static SastContext runAndAssertCSharp(File dir, String detectorId, Consumer<SastRuleConfig> changeConfig) {
    var qualifiedDetectorId = qualifyDetectorId(detectorId);
    var ctx = runCSharp(dir, qualifiedDetectorId, changeConfig);
    SastAssertions.assertThat(ctx).matchesIssues();

    return ctx;
  }

  @Nonnull
  private static String qualifyDetectorId(String detectorId) {
    return detectorId.startsWith("csharp.") ? detectorId : "csharp." + detectorId;
  }
}
