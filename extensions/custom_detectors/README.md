# Developing and Deploying Custom Detectors

A Xygeni **detector** is a piece of logic that detects a security issue in a scanned target system such as source code, a source code repository or a container image, a CI/CD system or another software tool. A detector has YAML (.yml) file that configures the detector, possibly an implementation class (.java), and optionally an AsciiDoc (.adoc) file to document the issues raised by the detector.

This section documents how to develop and deploy custom detectors.

In what follows, 
- `$PROJECT_DIR` will be used for the path to the Maven project containing your custom detectors code. 
- `$SCANNER_DIR` will be used for the path where the Xygeni scanner is installed.
- `<scan_type>` is the type of scan for your custom detector, one of `secrets`, `iac`, `misconfigurations`, `suspectdeps`, `malware` or `compliance`.

## Creating a Custom Detector

The general procedure for creating a custom detector is as follows:

1. Identify the source (input) to be scanned for issues. 
2. (First time only) Create a Maven project for the detector sources and unit tests. You may find a Maven project template that you may adapt to your needs. In what follows, the `$PROJECT_DIR` will be used for that project. 
3. Create a YAML (.yml) file in the `$PROJECT_DIR/src/resources/<scan_type>` directory.

> [!TIP]
> In the conf/<scan_type> directory in the scanner, you may find a `_template.yml_` file that you may edit. Please follow the instructions in the comments.

4. Create an implementation class in the `$PROJECT_DIR/src/main/java` directory, with your package name following standard Java conventions. You may find a template in the `$PROJECT_DIR/src/examples/<scan_type>` directory.

5. (Optional, recommended) Add a unit test for the detector.

6. Create an AsciiDoc (.adoc) file in the `$PROJECT_DIR/src/docs/<scan_type>` directory. Use the same name as your .yml file, but with an .adoc extension instead.

7. Deploy the detector with the scanner: call `mvn deploy -Dmaven.test.skip=true -DXYGENI_DIR=$XYGENI_DIR` so the compiled artifacts for your detector are deployed to your local scanner, in the `$XYGENI_DIR/conf/custom_detectors/<scan_type>`. Test your deployed detector with `xygeni ... --custom-detectors-dir=$XYGENI_DIR/conf/custom_detectors/<scan_type>`.

8. Once you are satisfied with your detector, you may upload your custom detectors with `xygeni util conf-upload --help`.

The following sections provide additional details on how to create custom detectors for a given type.

### Secrets Leak Detector

To create a secrets leak detector, typically it is not necessary to develop a Java class with the detection login. The default `com.depsdoctor.secrets.scanner.detector.impl.GenericSecretDetector` class is sufficient, allowing for purely declarative logic for the detection of the leak and its verification. Simply follow the instructions in the `$SCANNER_DIR/onf/secrets/_template.yml_`.

Example: A detector for a Gitlab Personal Access Token has the following YAML configuration:

```yaml
id: gitlab_token
enabled: yes
type: gitlab_token
description: GitLab Personal Access Token
severity: critical
confidence: highest

value:
  regex:
    pattern: '\bglpat-[0-9a-zA-Z\-=_]{20,22}\b'
    ignorecase: no

verifier:
  className: com.depsdoctor.secrets.scanner.detector.verifier.GitlabVerifier
  # action: do_nothing | increase_severity_when_verified | decrease_severity_when_not_verified | ignore_when_not_verified
  action: decrease_severity_when_not_verified
  properties:
    host: gitlab.com/api/v4/user
    tokenPrefix: Bearer

defaultPolicies:
  - Very_Strict
  - Standard
  - Essential
```

### IaC Flaws Detector

### CI/CD Misconfigurations Detector

### Suspect Dependency Detector

### Malware Evidence Detector

### Compliance Checkpoint and Standard



