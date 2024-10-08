package io.xygeni.extensions.custom_detectors.iac;

import com.depsdoctor.commons.Resources;
import com.depsdoctor.commons.file.FileType;
import com.depsdoctor.commons.io.Files;
import com.depsdoctor.commons.io.IO;
import com.depsdoctor.commons.yml.YmlUtils;
import com.depsdoctor.core.model.files.FileTypeHelper;
import com.depsdoctor.core.model.iac.IacFlaw;
import com.depsdoctor.core.model.iac.IacFlawsReport;
import com.depsdoctor.core.model.iac.IacFramework;
import com.depsdoctor.iac.scanner.config.DetectorConfig;
import com.depsdoctor.iac.scanner.config.IacScanConfig;
import com.depsdoctor.iac.scanner.config.IacScanConfigLoader;
import com.depsdoctor.iac.scanner.config.MultiDetectorConfig;
import com.depsdoctor.iac.scanner.detector.IacFlawDetector;
import com.depsdoctor.iac.scanner.detector.IacFlawDetectorLoader;
import com.depsdoctor.iac.scanner.engine.IacContext;
import com.depsdoctor.iac.scanner.engine.IacScanListener;
import com.depsdoctor.iac.scanner.xypol.PolicyEvalResult;
import com.depsdoctor.stan.scanner.parser.iac.model.IacTemplate;
import com.depsdoctor.stan.scanner.parser.iac.model.ansible.AnsibleTemplate;
import com.depsdoctor.stan.scanner.parser.iac.model.arm.ArmConfiguration;
import com.depsdoctor.stan.scanner.parser.iac.model.cf.CfConfiguration;
import com.depsdoctor.stan.scanner.parser.iac.model.docker.DockerfileTemplate;
import com.depsdoctor.stan.scanner.parser.iac.model.kubernetes.KubernetesTemplate;
import com.depsdoctor.stan.scanner.parser.iac.model.terraform.Configuration;
import com.depsdoctor.stan.scanner.parser.iac.parser.BaseParser;
import com.depsdoctor.stan.scanner.parser.iac.parser.ParseException;
import com.depsdoctor.stan.scanner.parser.iac.parser.ansible.AnsibleParser;
import com.depsdoctor.stan.scanner.parser.iac.parser.arm.ArmParser;
import com.depsdoctor.stan.scanner.parser.iac.parser.cf.CfParser;
import com.depsdoctor.stan.scanner.parser.iac.parser.docker.DockerfileParser;
import com.depsdoctor.stan.scanner.parser.iac.parser.helm.HelmParser;
import com.depsdoctor.stan.scanner.parser.iac.parser.kubernetes.KubernetesParser;
import com.depsdoctor.stan.scanner.parser.iac.parser.terraform.TerraformParser;
import com.google.common.collect.Lists;
import io.xygeni.sankxy.xypol.ast.Policy;
import io.xygeni.sankxy.xypol.parser.XypolParser;
import lombok.Data;
import org.assertj.core.api.Assertions;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.depsdoctor.core.model.files.FileTypeHelper.extensions;
import static io.xygeni.extensions.custom_detectors.TestHelper.getTestResourcesDir;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * IacRuleTestHelper - Helper for unit testing IaC flaw detectors.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class IacRuleTestHelper {
  private static final File TEST_DIR = new File(getTestResourcesDir(), "iac");

  public static IacContext runTerraform(String detectorId, IacFlawDetector rule, String path) {
    return runTerraform(detectorId, rule, path, dc -> {});
  }

  public static IacContext runTerraform(String detectorId, IacFlawDetector rule, String path, Consumer<DetectorConfig> onConfig) {
    Configuration conf = IacRuleTestHelper.parseTerraform(path);
    return run(detectorId, rule, IacFramework.terraform, path, conf, onConfig);
  }

  public static IacContext runDockerfile(String detectorId, IacFlawDetector rule, String path) {
    return runDockerfile(detectorId, rule, path, dc -> {});
  }

  public static IacContext runDockerfile(String detectorId, IacFlawDetector rule, String path, Consumer<DetectorConfig> onConfig) {
    DockerfileTemplate conf = IacRuleTestHelper.parseDockerfile(path);
    return run(detectorId, rule, IacFramework.dockerfile, path, conf, onConfig);
  }

  public static IacContext runArm(String detectorId, String path) {
    return runArm(detectorId, null, path, dc -> {});
  }

  public static IacContext runArm(String detectorId, IacFlawDetector rule, String path) {
    return runArm(detectorId, rule, path, dc -> {});
  }

  public static IacContext runArm(String detectorId, IacFlawDetector rule, String path, Consumer<DetectorConfig> onConfig) {
    ArmConfiguration conf = IacRuleTestHelper.parseArm(path);
    return run(detectorId, rule, IacFramework.arm, path, conf, onConfig);
  }

  public static IacContext runCf(String detectorId, String path) {
    return runCf(detectorId, null, path, dc -> {});
  }

  public static IacContext runCf(String detectorId, String path, Consumer<DetectorConfig> onConfig) {
    return runCf(detectorId, null, path, onConfig);
  }

  public static IacContext runCf(String detectorId, IacFlawDetector rule, String path, Consumer<DetectorConfig> onConfig) {
    CfConfiguration conf = IacRuleTestHelper.parseCf(path);
    return run(detectorId, rule, IacFramework.aws_cloudformation, path, conf, onConfig);
  }

  public static IacContext runAnsible(String detectorId, String path) {
    return runAnsible(detectorId, null, path, dc -> {});
  }

  public static IacContext runAnsible(String detectorId, String path, Consumer<DetectorConfig> onConfig) {
    return runAnsible(detectorId, null, path, onConfig);
  }

  public static IacContext runAnsible(String detectorId, IacFlawDetector rule, String path, Consumer<DetectorConfig> onConfig) {
    var confs = IacRuleTestHelper.parseAnsible(path);
    if(confs == null) return null;

    List<IacContext> ctxs = Lists.newArrayList();

    for(var conf : confs) {
      ctxs.add(run(detectorId, rule, IacFramework.ansible, path, conf, onConfig));
    }

    var ctx = ctxs.get(0);
    for(int i = 1; i < ctxs.size(); i++) {
      var nextCtx = ctxs.get(i);
      nextCtx.getReport().getFlaws().forEach(flaw -> ctx.addFlaw(flaw, null));
    }

    return ctx;
  }

  public static IacContext runK8s(String detectorId, String path) {
    return runK8s(detectorId, null, path, dc -> {});
  }

  public static IacContext runK8s(String detectorId, String path, Consumer<DetectorConfig> onConfig) {
    return runK8s(detectorId, null, path, onConfig);
  }

  public static IacContext runK8s(String detectorId, IacFlawDetector rule, String path, Consumer<DetectorConfig> onConfig) {
    var confs = IacRuleTestHelper.parseKubernetes(path);
    if(confs == null) return null;

    List<IacContext> ctxs = Lists.newArrayList();

    for(var conf : confs) {
      ctxs.add(run(detectorId, rule, IacFramework.kubernetes, path, conf, onConfig));
    }

    var ctx = ctxs.get(0);
    for(int i = 1; i < ctxs.size(); i++) {
      var nextCtx = ctxs.get(i);
      nextCtx.getReport().getFlaws().forEach(flaw -> ctx.addFlaw(flaw, null));
    }

    return ctx;
  }

  public static IacContext runHelm(String detectorId, String path) {
    return runHelm(detectorId, null, path, dc -> {});
  }

  public static IacContext runHelm(String detectorId, String path, Consumer<DetectorConfig> onConfig) {
    return runHelm(detectorId, null, path, onConfig);
  }

  public static IacContext runHelm(String detectorId, IacFlawDetector rule, String path, Consumer<DetectorConfig> onConfig) {
    var confs = IacRuleTestHelper.parseHelm(path);
    if(confs == null) return null;

    List<IacContext> ctxs = Lists.newArrayList();

    for(var conf : confs) {
      ctxs.add(run(detectorId, rule, IacFramework.kubernetes, path, conf, onConfig));
    }

    var ctx = ctxs.get(0);
    for(int i = 1; i < ctxs.size(); i++) {
      var nextCtx = ctxs.get(i);
      nextCtx.getReport().getFlaws().forEach(flaw -> ctx.addFlaw(flaw, null));
    }

    return ctx;
  }

  public static IacContext run(
    String detectorId, IacFlawDetector rule, IacFramework framework, String path, IacTemplate template,
    Consumer<DetectorConfig> onConfig
  ) {
    IacContext ctx = IacRuleTestHelper.context(path);
    ctx.getConfiguration().setTimeout(0);

    var dc = load(detectorId, framework);
    // the rule under test is always enabled irrespectively of the default configuration
    dc.setEnabled(true);
    onConfig.accept(dc);
    ctx.getConfiguration().addDetector(dc);

    if(rule == null) {
      rule = loadRule(detectorId, framework, ctx);
    }

    rule.configure(dc, ctx.getConfiguration());

    try {
      rule.initialize(ctx);
      rule.detect(template, ctx);
    } finally {
      rule.terminate(ctx);
    }

    ctx.addProperty("IaC_template", template);
    return ctx;
  }

  @SuppressWarnings("unchecked")
  public static <T extends IacTemplate> T template(IacContext ctx) {
    return (T)ctx.getProperty("IaC_template");
  }

  public static DetectorConfig load(String id, IacFramework framework) {
    var config = new IacScanConfigLoader().loadDetector(id);
    if(!(config instanceof MultiDetectorConfig)) return config;

    return ((MultiDetectorConfig) config).unpack().stream()
      .filter(d -> framework == null || d.getFramework().equals(framework))
      .findFirst()
      .orElse(null);
  }

  public static void assertResult(IacContext ctx, Collection<String> fail) {
    var seen = ctx.flaws().getFlaws().stream()
      .map(IacFlaw::getResource).filter(Objects::nonNull)
      .collect(Collectors.toList());
    assertThat(seen).containsExactlyInAnyOrderElementsOf(fail);
  }

  public static void assertResult(IacContext ctx, String expected) {
    try {
      PassFail pf = expected(expected);
      assertResult(ctx, pf.getFail());

    } catch (IOException e) {
      fail("Cannot load expected YAML file: %s, due to: %s", expected, e.getMessage());
    }
  }


  /**
   * Checks if the results of evaluating a XYPOL policy matches the expected pass / fail resources.
   *
   * @param result The pass/fail resource
   * @param pass Expected resources with PASS result
   * @param fail Expected resources with FAIL result
   */
  public static void assertResult(Collection<PolicyEvalResult> result, Collection<String> pass, Collection<String> fail) {
    var seenPass = result.stream()
      .filter(r -> r.getStatus().isTrue()).map(PolicyEvalResult::getResource)
      .collect(Collectors.toSet());
    var seenFail = result.stream()
      .filter(r -> r.getStatus().isFalse()).map(PolicyEvalResult::getResource)
      .collect(Collectors.toSet());

    assertThat(seenPass).containsExactlyInAnyOrderElementsOf(pass);
    assertThat(seenFail).containsExactlyInAnyOrderElementsOf(fail);
  }

  /**
   * Checks if the results of evaluating a XYPOL policy matches the expected pass / fail resources specified in YAML file
   * with pass / fail fields.
   *
   * @param result The pass/fail resource
   * @param expected Path to a YAML file, or directory containing {@code expected.yaml}, relative to test "detector" directory.
   */
  public static void assertResult(Collection<PolicyEvalResult> result, String expected) {
    try {
      PassFail pf = expected(expected);
      assertResult(result, pf.getPass(), pf.getFail());

    } catch (IOException e) {
      fail("Cannot load expected YAML file: %s, due to: %s", expected, e.getMessage());
    }
  }

  /**
   * Checks results with expected flaws given as "resource@line".
   * Assertion fails if false positives (unexpected flaw found) or
   * false negatives (expected flaw was not detected)
   */
  public static void assertExpected(IacContext ctx, List<String> expected) {
    Function<IacFlaw, String> keyer = flaw -> flaw.getResource() + "@" + flaw.getBeginLine();
    List<String> falsePositives = ctx.flaws().stream().map(keyer).collect(Collectors.toList());
    List<String> falseNegatives = Lists.newArrayList(expected);

    for(var flaw : ctx.flaws()) {
      String key = keyer.apply(flaw);
      if(expected.contains(key)) {
        falseNegatives.remove(key); falsePositives.remove(key);
      }
    }

    String explain = "";
    if(!falseNegatives.isEmpty()) explain += "\nNot detected (FN): " + falseNegatives;
    if(!falsePositives.isEmpty()) explain += "\nNot expected (FP): " + falsePositives;

    if(!falsePositives.isEmpty() || !falseNegatives.isEmpty()) {
      Assertions.fail(explain);
    }
  }

  public static void assertExpected(IacContext ctx, String... expected) {
    assertExpected(ctx, List.of(expected));
  }

  /** Returns parsed Terraform configuration for the file (or directory) tfile (path relative to resources/detectors)    */
  public static Configuration parseTerraform(String tfile) throws ParseException {
    return (Configuration)parseTemplate(tfile, FileType.terraform, TerraformParser.class);
  }

  public static DockerfileTemplate parseDockerfile(String tfile) throws ParseException {
    return (DockerfileTemplate)parseTemplate(tfile, FileType.dockerfile, DockerfileParser.class);
  }

  public static ArmConfiguration parseArm(String path) throws ParseException {
    var file =  new File(TEST_DIR, path);
    if(file.isFile()) return (ArmConfiguration)parseTemplate(path, FileType.json, ArmParser.class);

    return (ArmConfiguration)parseDir(file, FileType.json, ArmParser.class);
  }

  public static CfConfiguration parseCf(String path) throws ParseException {
    var file =  new File(TEST_DIR, path);

    return (CfConfiguration)parseDir(file, null, CfParser.class);
  }

  public static List<KubernetesTemplate> parseKubernetes(String path) throws ParseException {
    var file =  new File(TEST_DIR, path);
    if(file.isDirectory()) {
      FileFilter fileFilter = f -> extensions(FileType.yaml).stream().anyMatch(ext -> f.getName().contains(ext));
      var files = file.listFiles(fileFilter);
      if(files == null) return null;

      return Arrays.stream(files)
        .filter(File::isFile)
        .map(f -> (KubernetesTemplate)parseTemplate(
          Files.relativize(f, TEST_DIR), FileType.yaml, KubernetesParser.class)
        )
        .collect(Collectors.toList());

    } else {
      return List.of((KubernetesTemplate)parseTemplate(path, FileType.yaml, KubernetesParser.class));
    }
  }

  public static List<KubernetesTemplate> parseHelm(String path) throws ParseException {
    var file =  new File(TEST_DIR, path);
    if(file.isDirectory()) {
      FileFilter fileFilter = f -> extensions(FileType.yaml).stream().anyMatch(ext -> f.getName().contains(ext));
      List<File> files = Lists.newArrayList();

      try (Stream<Path> stream = java.nio.file.Files.walk(file.toPath())) {
        stream.filter(reachedFile -> fileFilter.accept(reachedFile.toFile()))
            .forEach(reachedFile -> files.add(reachedFile.toFile()));
      } catch (IOException ignored) { }

      return files.stream()
          .filter(File::isFile)
          .map(f -> (KubernetesTemplate)parseTemplate(
              Files.relativize(f, TEST_DIR), FileType.yaml, HelmParser.class, file)
          )
          .collect(Collectors.toList());

    } else {
      return List.of((KubernetesTemplate)parseTemplate(path, FileType.yaml, HelmParser.class, file));
    }
  }

  public static List<AnsibleTemplate> parseAnsible(String path) throws ParseException {
    var file =  new File(TEST_DIR, path);
    if(file.isDirectory()) {
      FileFilter fileFilter = f -> extensions(FileType.yaml).stream().anyMatch(ext -> f.getName().contains(ext));
      var files = file.listFiles(fileFilter);
      if(files == null) return null;

      return Arrays.stream(files)
          .filter(File::isFile)
          .map(f -> (AnsibleTemplate)parseTemplate(
              Files.relativize(f, TEST_DIR), FileType.yaml, AnsibleParser.class)
          )
          .collect(Collectors.toList());

    } else {
      return List.of((AnsibleTemplate)parseTemplate(path, FileType.yaml, AnsibleParser.class));
    }
  }

  /** Loads the Terraform Configuration in the given file (or directory containing {@code main.tf}) */
  public static IacTemplate parseTemplate(String tfile, FileType type) throws ParseException {
    switch (type) {
      case terraform: return parseTemplate(tfile, type, TerraformParser.class);
      case dockerfile: return parseTemplate(tfile, type, DockerfileParser.class);
      case json: return parseTemplate(tfile, type, ArmParser.class);
    }
    throw new ParseException("No known parser for " + type.name());
  }

  public static <T extends BaseParser> IacTemplate parseTemplate(String tfile, FileType fileType, Class<T> parserClazz)
      throws ParseException {
    return parseTemplate(tfile, fileType, parserClazz, null);
  }

  public static <T extends BaseParser> IacTemplate parseTemplate(
      String tfile, FileType fileType, Class<T> parserClazz, File basedir
  ) throws ParseException {
    File f = file(tfile, fileType);
    if(basedir == null) basedir = f.getParentFile();

    try {
      BaseParser p = parserClazz.getDeclaredConstructor().newInstance();
      return p.parse(f, tfile, fileType, basedir);

    } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
      throw new ParseException("Illegal parser class", e);
    }
  }

  public static <T extends BaseParser> IacTemplate parseDir(File dir, FileType fileType, Class<T> parserClazz)
      throws ParseException {
    try {
      BaseParser p = parserClazz.getDeclaredConstructor().newInstance();
      return p.parse(dir, dir.getPath(), fileType, dir);

    } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
      throw new ParseException("Illegal parser class", e);
    }
  }

  public static File file(String path, FileType fileType) {
    File tfile = new File(TEST_DIR, path);
    if(tfile.isDirectory()) tfile = new File(tfile, FileTypeHelper.filename(fileType));
    assertThat(tfile).isFile();
    return tfile;
  }

  public static Policy policy(String xypol) {
    return new XypolParser(new StringReader(xypol)).Policy();
  }

  public static IacContext context(String dir) {
    File directory = new File(TEST_DIR, dir);
    return context(directory);
  }

  public static IacContext context(File directory) {
    if(directory.isFile()) directory = directory.getParentFile();
    var config = new IacScanConfig();
    var report = new IacFlawsReport("test", directory, false, null);

    return IacContext.builder()
        .projectName("test").directory(directory)
        .configuration(config).report(report)
        .listener(IacScanListener.NULL)
        .build();
  }

  @Data
  public static class PassFail {
    private List<String> pass;
    private List<String> fail;
  }

  /** Loads expected.yaml with pass / fail resources for a XYPOL rule */
  public static PassFail expected(String path) throws IOException {
    File f = new File(TEST_DIR, path);
    if(f.isFile() && f.getName().endsWith(".tf")) f = f.getParentFile();
    if(f.isDirectory()) f = new File(f, "expected.yaml");
    assertThat(f).as("%s test result spec does not exist").isFile();

    try(var is = IO.openInputStream(f)) {
      return new Yaml(YmlUtils.safeConstructor(PassFail.class)).load(is);
    }
  }

  public static File getTestResourcesFile(String relativePath) {
    File f = new File(getTestResourcesDir(), relativePath);
    assertThat(f).isFile();
    return f;
  }

  private static IacFlawDetector loadRule(String detectorId, IacFramework framework, IacContext ctx) {
    var detectors = new IacFlawDetectorLoader().loadDetectors(
      ctx.getConfiguration(),
      d -> detectorId.equals(d.getId()) && (framework == null || d.getFramework().equals(framework)),
      Resources.getThreadClassLoader()
    );

    assertThat(detectors.size()).isEqualTo(1);
    return detectors.get(0);
  }
}
