package io.xygeni.extensions.custom_detectors.secrets;

import com.depsdoctor.commons.Resources;
import com.depsdoctor.commons.file.FileType;
import com.depsdoctor.commons.git.Git;
import com.depsdoctor.core.model.secrets.SecretsReport;
import com.depsdoctor.secrets.scanner.config.SecretsConfig;
import com.depsdoctor.secrets.scanner.config.SecretsConfigLoader;
import com.depsdoctor.secrets.scanner.detector.SecretDetectorLoader;
import com.depsdoctor.secrets.scanner.engine.SecretsContext;
import com.depsdoctor.secrets.scanner.engine.SecretsEngine;
import com.depsdoctor.secrets.scanner.engine.SecretsListener;
import com.depsdoctor.secrets.scanner.parser.DefaultParser;
import com.depsdoctor.secrets.scanner.parser.Entry;
import io.xygeni.extensions.custom_detectors.TestHelper;
import org.assertj.core.api.Assertions;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

import static io.xygeni.extensions.custom_detectors.TestHelper.getTestResourcesDir;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * SecretTestHelper -
 *
 * @author lrodriguez
 * @version 01-Nov-2024 (lrodriguez)
 */
public class SecretTestHelper {

  private static final SecretsConfigLoader loader = new SecretsConfigLoader(false);

  private static final File secretConfigDir = new File(
    TestHelper.getModuleBasedir(), "src/main/resources/secrets"
  );

  /** Run secrets scanner on the given directory, using a detectors config file */
  public static SecretsContext runOnFiles(String testName, File dir, String configFile) {
    return runOnFiles(testName, dir, configFile, conf -> {});
  }

  public static SecretsContext runOnText(String detectorId, String text, String configFile) {
    var ctx = buildContext(detectorId, getTestResourcesDir());
    var conf = ctx.getConfiguration();
    conf.setNoVerify(false);

    // Load detector configurations to test
    load(configFile, conf);
    assertThat(conf.getDetectors()).isNotEmpty();
    // ensure that, for testing, all detectors are enabled
    conf.getDetectors().forEach(dc -> dc.setEnabled(true));

    // Load the detectors
    var loaded = new SecretDetectorLoader()
      .loadDetectors(conf, d -> true, Resources.getThreadClassLoader());

    loaded.forEach(d -> d.initialize(ctx));

    var parser = new DefaultParser();
    var baseEntry = Entry.with(new File(ctx.getDirectory(), detectorId), FileType.plaintext);
    var entries = parser.process(new StringReader(text), baseEntry);
    assertThat(entries).isNotNull();

    entries.forEach(e -> {
      loaded.forEach(d -> d.detect(e, ctx));
    });

    loaded.forEach(d -> d.terminate(ctx));

    return ctx;
  }

  /**
   * Same as {@link #runOnFiles(String, File, String)}, but allows to modify
   * the configuration in the test with changeConfig before instantiating the detectors
   */
  public static SecretsContext runOnFiles(String testName, File dir, String configFile, Consumer<SecretsConfig> changeConfig) {
    var ctx = buildContext(testName, dir);
    var conf = ctx.getConfiguration();
    conf.setTimeout(0);
    conf.setParsingTimeout(0);
    conf.setNoVerify(false);

    // Load detector configurations to test
    load(configFile, conf);
    assertThat(conf.getDetectors()).isNotEmpty();
    // ensure that, for testing, all detectors are enabled
    conf.getDetectors().forEach(dc -> dc.setEnabled(true));

    changeConfig.accept(conf);

    // Load the detectors
    var loaded = new SecretDetectorLoader()
      .loadDetectors(conf, d -> true, Resources.getThreadClassLoader());

    assertThat(loaded).hasSameSizeAs(conf.getDetectors());

    SecretsEngine engine = new SecretsEngine();
    engine.setDetectors(loaded);

    try(var stream = Files.walk(dir.toPath()).map(Path::toFile).filter(File::isFile)) {
      engine.scanSecrets(stream, ctx);
      return ctx;

    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * Load SecretsConfig from classpath, the detector configuration file (.yml extension optional),
   * and adds detectors to the config
   */
  public static SecretsConfig load(String fname) {
    SecretsConfig conf = loader.load();
    load(fname, conf);
    return conf;
  }

  /** Load detectors for the given detector configuration file (.yml extension optional) and adds them to the config */
  public static void load(String fname, SecretsConfig config) {
    var detectors = loader.loadDetectors(configFile(fname));
    detectors.forEach(config::addDetector);
  }

  private static File configFile(String fname) {
    if(!fname.endsWith(".yml")) fname += ".yml";
    File f = new File(secretConfigDir, fname);
    Assertions.assertThat(f).isFile();
    return f;
  }

  public static SecretsContext buildContext(String projName, File dir) {
    SecretsConfig conf = new SecretsConfig();
    conf.setGitRoot(Git.getRootDirectory(dir));
    SecretsReport report = new SecretsReport(projName, dir, null, true, null);
    return SecretsContext.builder()
      .projectName(projName)
      .directory(dir)
      .report(report)
      .listener(SecretsListener.NULL)
      .configuration(conf)
      .build();
  }

}
