# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Xygeni-Extensions is a repository for extending the Xygeni software supply chain security platform. It contains examples and documentation for:
- Custom detectors (secrets, IaC, CI/CD misconfigurations)
- Custom remediations
- Third-party report upload converters
- Exporters for third-party tools (Kiuwan, SonarQube)

## Build Commands

### Custom Detectors (extensions/custom_detectors)

Build and deploy to local Xygeni scanner:
```bash
cd extensions/custom_detectors
mvn install -Dxygeni.home=$XYGENI_DIR -Dxygeni.version=x.y.z
```

Skip tests during build:
```bash
mvn install -Dmaven.test.skip=true -Dxygeni.home=$XYGENI_DIR
```

Run tests:
```bash
mvn test
```

Run a single test:
```bash
mvn test -Dtest=ClassName
```

Run integration tests:
```bash
mvn verify
```

### Report Upload Converters (e.g., extensions/report_upload/secrets/trufflehog)
Each converter has its own pom.xml and follows the same Maven commands.

## Project Structure

```
extensions/
├── custom_detectors/      # Custom security detectors
│   ├── src/main/java/     # Detector implementations
│   ├── src/main/resources/
│   │   ├── secrets/       # Secret detector YAML configs
│   │   ├── iac/           # IaC detector YAML configs
│   │   └── misconfigurations/  # CI/CD misconfiguration YAML configs
│   └── doc/               # Detector type documentation
├── custom_remediations/   # Remediation playbooks
│   └── src/main/resources/remediation/
│       ├── secret/        # Secret remediation playbooks
│       └── misconfiguration/  # Misconfiguration remediation playbooks
├── report_upload/         # Third-party report converters
│   └── secrets/trufflehog/  # Example: Trufflehog converter
└── exporter/              # Exporters for third-party tools
    ├── kiuwan/            # Kiuwan SAST exporter
    └── sonarqube/         # SonarQube exporter
```

## Key Concepts

### Detector Structure
A detector requires:
1. **YAML config** (`.yml`) in `src/main/resources/<scan_type>/` - detector configuration
2. **Java class** (optional) - custom detection logic extending Xygeni base classes
3. **AsciiDoc** (`.adoc`) (optional) - documentation for issues raised

Scan types: `secrets`, `iac`, `misconfigurations`, `suspectdeps`, `malware`, `compliance`

### Remediation Structure
Remediation playbooks are YAML files in `conf.custom/remediation/<scan_type>/` with:
- `id`: matches the detector ID
- `issueKind`: secret, misconfiguration, vulnerability, etc.
- `on`: where it runs (scan, guardrail, backend, workflow)
- `playbook`: remediation logic script

### Report Converter Structure
Converters require:
1. **Loader class** - deserializes external tool report
2. **Converter class** - transforms to Xygeni standard model
3. **Registration** in `xygeni.custom.report-upload.yml`

## Environment Configuration

The `XYGENI_DIR` environment variable must point to the Xygeni scanner installation.

Key Maven properties:
- `xygeni.home`: Path to Xygeni scanner (defaults to `$XYGENI_DIR`)
- `xygeni.version`: Scanner version (e.g., `4.38.0`)

## Testing Detectors

Test a custom detector with the scanner:
```bash
xygeni <scan_type> --detectors=<detector_id> <target>
```

Upload custom configuration to Xygeni platform:
```bash
xygeni util conf-upload
```

## Java Requirements

- Java 11+ required
- JUnit 5 for tests
- Lombok for boilerplate reduction

## SAST Rules Development

SAST (Static Application Security Testing) detectors are developed in the main DepsDoctor repository (`/home/lrodriguez/projects/xygeni/DepsDoctor`), not in xygeni-extensions. This section provides context for cross-repository work.

### SAST Scanner Architecture

The SAST scanner supports multiple languages with a plugin architecture:
- Java, JavaScript/TypeScript, Python, Go, C#, PHP, Swift, SQL
- Additional: HCL, Dockerfile, HTML, XML, YAML, Makefile, Jenkinsfile

**Detector Types:**
- `regular` - Navigation-based AST analysis detectors
- `tainting` - Data flow analysis detectors tracking tainted data
- `framework` - Framework-specific security rules (e.g., Spring, Express, React, Vapor)

### Adding New SAST Detectors (in DepsDoctor)

For each new detector, create:

1. **Java Rule Class** in `SastScanner/src/main/java/io/xygeni/sast/scanner/detector/[language]/[regular|tainting]/[DetectorName].java`
   - Extend `[Language]Rule` or `[Language]TaintingRule` base class
   - Override `checkCall()` or `checkNode()` methods
   - Use `createIssue()` to report vulnerabilities

2. **YAML Configuration** in `SastScanner/src/main/resources/sast/[language]/[language].[detector_id].yml`
   - Define detector metadata (id, name, severity, CWE, OWASP mappings)

3. **AsciiDoc Documentation** in `SastScanner/src/doc/asciidoc/sast/detectors/[language]/[language].[detector_id].adoc`

4. **Test Class** in `SastScanner/src/test/java/io/xygeni/sast/scanner/detector/[language]/[regular|tainting]/[Language][DetectorName]Test.java`
   - Test regression cases using `SastAssertions`

5. **Test Resources** in `SastScanner/src/test/resources/detector/[language]/[detector_id]/regression/`

### SAST Rule Pattern Example
```java
public class MyDetector extends SwiftRule {
  @Override
  protected void checkCall(SwiftCallSignature call, SastContext ctx) {
    if (matches dangerous pattern) {
      createIssue(call, ctx, "Explanation {0}", arg);
    }
  }
}
```

### SAST Test Pattern
```java
@Test
public void testRegression() {
  var file = new File(DETECTOR_DIR, "regression");
  var ctx = runLanguage(file, DETECTOR_ID);
  SastAssertions.assertThat(ctx).matchesIssues();
}
```

### SAST Test Conventions
- Test files follow the pattern: `[Language][DetectorName]Test.java`
- Regression test resources are in: `src/test/resources/detector/[language]/[detector_name]/regression/`
- Tests use `SastAssertions.assertThat(ctx).matchesIssues()` to validate expected issues