package io.xygeni.extensions.custom_detectors.sast.test.helpers;

import com.depsdoctor.commons.config.DepsDoctorConfig;
import com.depsdoctor.commons.config.DepsDoctorConfigLoader;
import com.depsdoctor.core.model.sast.CodeVulnerability;
import com.depsdoctor.core.model.sast.SastCodeVulnerabilityKind;
import com.depsdoctor.core.model.sast.SastReport;
import com.depsdoctor.core.utils.malware.MalwareEvidencesReportWriter;
import io.xygeni.sankxy.core.exception.AnalyzerTaskException;
import io.xygeni.sankxy.core.exception.AnalyzerTaskInternalException;
import io.xygeni.sankxy.core.software.Language;
import io.xygeni.sankxy.core.task.FileAnalyzerTask;
import io.xygeni.sast.scanner.cli.SastFilesSupplier;
import io.xygeni.sast.scanner.config.SastRuleConfig;
import io.xygeni.sast.scanner.config.SastScanConfig;
import io.xygeni.sast.scanner.config.SastScanConfigLoader;
import io.xygeni.sast.scanner.detector.SastRule;
import io.xygeni.sast.scanner.engine.SastContext;
import io.xygeni.sast.scanner.engine.SastEngine;
import io.xygeni.sast.scanner.engine.SastOperation;
import io.xygeni.sast.scanner.engine.SastScanArgs;
import io.xygeni.sast.scanner.engine.SastScanListener;
import io.xygeni.sast.scanner.parser.BaseParser;
import io.xygeni.sast.scanner.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static io.xygeni.extensions.custom_detectors.TestHelper.TEST_DIR;
import static io.xygeni.extensions.custom_detectors.TestHelper.getTestResourcesDir;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * SastDetectorTestHelper - Helper for unit testing SAST detectors.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class SastDetectorTestHelper {

  public static final File SAST_DETECTORS_TEST_DIR = new File(TEST_DIR, "sast");

  private static final DepsDoctorConfig global = new DepsDoctorConfigLoader().load();
  private static final Logger log = LoggerFactory.getLogger(SastDetectorTestHelper.class);

  public static SastScanConfig scanConfig() {
    var sc = new SastScanConfig();
    sc.setGlobalConfig(global);
    return sc;
  }

  public static SastContext context(SastFilesSupplier fs) {
    var directory = fs.getDirectory();
    if(directory.isFile()) directory = directory.getParentFile();
    var config = fs.getConfig();

    var report = new SastReport(
        "test", directory, false, null
    );

    return SastContext.builder()
        .projectName("test").directory(directory)
        .filesSupplier(fs)
        .configuration(config).report(report)
        .listener(SastScanListener.NULL)
        .build();
  }

  public static SastScanArgs scanArgs(File dir) {
    var filesOptions = new SastScanArgs.FilesOptions(
        dir, null, null, false, true
    );
    var configOptions = new SastScanArgs.ConfigOptions(
        SastScanConfigLoader.DEFAULT_CONFIG, false, MalwareEvidencesReportWriter.BASELINE_FILENAME, null,
        new String[]{}, new String[]{}, new SastCodeVulnerabilityKind[]{}, new SastCodeVulnerabilityKind[]{},
        null, null
    );
    var languagesOptions = new SastScanArgs.LanguageOptions(
        Set.of(Language.java, Language.javascript), Collections.emptySet()
    );

    return new SastScanArgs(SastOperation.scan, languagesOptions,"test", null, filesOptions, configOptions);
  }

  //<editor-fold desc="RUN">
  public static SastContext runOnDir(String detectorId) {
    var dir = new File(getTestResourcesDir(), "detector" + File.separator + detectorId);
    return run(dir, f -> true, detectorId, c -> {});
  }

  public static SastContext runOnFile(File dir, String fName, String detectorId) {
    return run(dir, f -> f.getName().equals(fName), detectorId, c -> {});
  }

  public static SastContext runOnFile(
      File dir, String fName, String detectorId, Consumer<SastRuleConfig> changeConfig
  ) {
    return run(dir, f -> f.getName().equals(fName), detectorId, changeConfig);
  }

  public static SastContext runOnDir(File dir, String detectorId) {
    return run(dir, f -> true, detectorId, c -> {});
  }

  public static SastContext runOnDir(File dir, Predicate<File> pred, String detectorId) {
    return run(dir, pred, detectorId, c -> {});
  }

  public static SastContext run(
      File dir, Predicate<File> pred, String detectorId, Consumer<SastRuleConfig> changeConfig
  ) {
    var config = scanConfig();
    var fs = new SastFilesSupplier(
        dir, config, false, true
    );
    if(pred != null) fs.setFilter(pred::test);

    var ctx = context(fs);
    var scanArgs = scanArgs(ctx.getDirectory());
    var engine = new SastEngine();

    engine.setScanListener(new SastScanListener() {
      @Override
      public void onParseFailed(File file, ParseException e, BaseParser parser, SastContext ctx) {
        System.err.printf("Parse failed for file %s, parser %s: %s %n", ctx.relativePath(file), parser.getName(), e.getMessage());
      }

      @Override
      public void onRuleInitializeFailed(SastRule rule, AnalyzerTaskInternalException e, SastContext ctx) {
        System.err.printf("Rule %s initialization failed: %s %n", rule.getId(), e.getMessage());
      }

      @Override
      public void onTaskFailed(File file, AnalyzerTaskException ex, FileAnalyzerTask t, SastContext ctx) {
        //System.err.printf("Task %s failed on file %s: %s %n", t.getId(), ctx.relativePath(file), ex.getMessage());
      }

      @Override
      public void onVulnerabilityFound(CodeVulnerability vulnerability, SastRule rule, SastContext ctx) {
        log.info("Vulnerability found: {}", vulnerability);
      }
    });

    ctx.getConfiguration().setTimeout(0);
    ctx.getConfiguration().setFileTimeout(0);
    var detectorConfig = new SastScanConfigLoader().loadRule(detectorId);
    if(detectorConfig == null) {
      throw new IllegalArgumentException("No detector config found for id: " + detectorId);
    }

    detectorConfig.setEnabled(true);
    changeConfig.accept(detectorConfig);
    ctx.getConfiguration().addRule(detectorConfig);

    // run
    return engine.scan(fs, scanArgs, ctx.getConfiguration());
  }

  public static SastContext runAll(File dir) {
    return runAll(dir, f -> true, d -> true);
  }

  public static SastContext runAll(File dir, Predicate<File> pred, Predicate<SastRuleConfig> detectorPred) {
    var config = scanConfig();
    var fs = new SastFilesSupplier(
        dir, config, false, true
    );
    if(pred != null) fs.setFilter(pred::test);

    var ctx = context(fs);
    var scanArgs = scanArgs(ctx.getDirectory());
    var engine = new SastEngine();

    engine.setScanListener(new SastScanListener() {
      @Override
      public void onParseFailed(File file, ParseException e, BaseParser parser, SastContext ctx) {
        System.err.printf("Parse failed for file %s, parser %s: %s %n", ctx.relativePath(file), parser.getName(), e.getMessage());
      }

      @Override
      public void onRuleInitializeFailed(SastRule rule, AnalyzerTaskInternalException e, SastContext ctx) {
        System.err.printf("Rule %s initialization failed: %s %n", rule.getId(), e.getMessage());
      }

      @Override
      public void onTaskFailed(File file, AnalyzerTaskException ex, FileAnalyzerTask t, SastContext ctx) {
        //System.err.printf("Task %s failed on file %s: %s %n", t.getId(), ctx.relativePath(file), ex.getMessage());
      }

      @Override
      public void onVulnerabilityFound(CodeVulnerability vulnerability, SastRule rule, SastContext ctx) {
        log.info("Vulnerability found: {}", vulnerability);
      }
    });

    var sastConfig = ctx.getConfiguration();
    sastConfig.setTimeout(0);
    sastConfig.setFileTimeout(0);
    var configLoader = new SastScanConfigLoader();
    configLoader.merge(sastConfig, sastConfig.getGlobalConfig());

    sastConfig.getRules()
        .forEach(rule -> rule.setEnabled(detectorPred.test(rule)));

    // run
    return engine.scan(fs, scanArgs, ctx.getConfiguration());
  }
  //</editor-fold>

  public static void dumpJson(SastContext ctx) {
    ctx.getReport().getIssues().forEach(System.out::println);
  }

  public static void dump(SastContext ctx) {
    ctx.getReport().getIssues().forEach(v -> System.out.println(toString(v)));
  }

  public static String toString(CodeVulnerability v) {
    return v.getDetector() + ": " + v.getExplanation() +
      "\n\t[" + v.getLocation().getFilepath() + "@" + v.getLocation().getBeginLine() + "]: " + v.getCode();
  }


  public static Stream<File> listFiles(File dir) {
    return listFiles(dir, f -> true);
  }

  public static Stream<File> listFiles(File dir, Predicate<File> pred) {
    assertThat(dir).isNotNull();
    assertThat(dir).isDirectory();

    List<File> files = null;
    try(Stream<Path> paths = Files.find(dir.toPath(),
        Integer.MAX_VALUE,
        (filePath, fileAttr) -> fileAttr.isRegularFile())) {

      files = paths.map(Path::toFile).collect(Collectors.toList());
    } catch (IOException ignored) { }

    assertThat(files).isNotNull();
    assertThat(files).isNotEmpty();

    return files.stream()
        .filter(file -> !file.isDirectory() && pred.test(file));
  }
}
