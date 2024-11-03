# Secrets Leak Detector

The [Secrets Scanner](https://docs.xygeni.io/xygeni-products/secrets-security/secrets-scanner) detects potential hard-coded secrets in source code and in other places, such as commits in git history or container images.

The secrets engine traverses all files of a filesystem directory, or alternatively from file changes in commits from the git history, or from layers in a container image tarball. Each file seen is tokenized or parsed accordingly to its type, and key-value pairs potentially holding hardcoded secrets are extracted in an `Entry` object. For each entry, enabled detectors run, typically looking for patterns in the key or the value for each specific type of secret. When a potential secret is found, it is reported as a potential leak, by creating a `PotentialSecret` object that it is added to the findings in the `SecretsContext`.

A detector may include a **verifier** that could check if the potential secret found is indeed active, to reduce the rate of false positives, and a **remediator** for fully automatic or user-controlled remediation (typically to revoke, rotate or deactivate a leaked credential, when possible and convenient).

## Quick Start

Imagine that you want to add a detector for Dropbox (short-lived) access tokens, including verifier and remediator. 
This example is chosen because it is simple and easy to implement.

### Investigate the secret format and the ways for verification and remediation

Dropbox short-lived access tokens start with 'sl.' followed by between 130 and 140 alphanumeric characters with some dash and underscore characters. A simple regular expression will match such tokens. To verify the validity of the token, Dropbox provides a https://www.dropbox.com/developers/documentation/http/documentation#check-user[/check/user] API endpoint that returns 200 if the token is valid. And to remediate the leak, the https://www.dropbox.com/developers/documentation/http/documentation#auth-token-revoke[/auth/token/revoke] API endpoint is available. 

### Implement the (declarative) detector and verifier

Create a new [custom_dropbox_token.yml](../src/main/resources/secrets/custom_dropbox_token.yml), You can follow the [template YAML](../src/main/resources/secrets/_template.yml_). Please note the following:

- The pattern for the Dropbox token will be `\bsl\.[A-Za-z0-9\-\_]{130,140}\b`. The pattern is between '\b' delimiters to ensure it is a whole word. 
- 
- The verifier uses the default ApiVerifier which can be configured with the url, method, and the prefix 'Bearer' needed in the Authorization header:

```yaml
verifier:
  className: com.depsdoctor.secrets.scanner.detector.verifier.ApiVerifier
  # action: do_nothing | increase_severity_when_verified | 
  # decrease_severity_when_not_verified | ignore_when_not_verified
  action: set_info_when_not_verified
  properties:
    host: api.dropboxapi.com/2/check/user
    method: POST
    tokenPrefix: Bearer
```

The `action` tells what to do when the secret is verified as valid or not. In this case, the secret severity is set to 'info' to indicate that inactive token does not pose any risk, but you can set `ignore_when_not_verified` which will remove the secret from the findings.

You may add a unit test that 

### Add remediation playbook

Create a new [custom_dropbox_token.yml](../../custom_remediations/src/main/resources/remediation/secret/custom_dropbox_token.yml). You can follow the [template YAML](../../custom_remediations/src/main/resources/remediation/_template.yml_). This remediation playbook is simple:

```java
  // Get the token in clear
  dropbox_token = secret.decrypt(issue);
  require exists(dropbox_token);
  // invoke the self-revoke endpoint, authenticating with the leaked token
  api(
    'https://api.dropbox.com/2', 'POST', '/auth/token/revoke', 
    token = dropbox_token, body = 'null' 
  );
```

### Add the custom detector to the scanner

You can copy the YAML files to the `$SCANNER_DIR/conf.custom/secrets` directory (detector YAML) and the `$SCANNER_DIR/conf.custom/remediation/secret` directory (remediation YAML). 

Alternatively, the build will do this for you. If you have maven installed, go to the `extensions/custom_detectors` directory and run `mvn package`. This will build all customizations, copy the configuration files to the `$SCANNER_DIR/conf.custom` directory, and the packaged jar file to the `$SCANNER_DIR/lib.custom`.

You can now run the scanner with the new detector, using `xygeni secrets ...`, or alternatively `xygeni secrets --detectors=custom_dropbox_token` to test your custom detector separately. 
You may also use the `xygeni util conf-upload` command to upload your custom detectors to the Xygeni platform.

### Add unit test for detector, verifier and remediation playbook

After deploying your detector, it is recommended to add a unit test for automated testing. See the [unit test](../src/test/java/io/xygeni/extensions/custom_detectors/secrets/DropboxDetectorTest.java) for our custom dropbox detector as an example.

Running `mvn test` will run the unit tests. 

## Declarative Detector

To create a secrets leak detector, typically it is _not necessary_ to develop a Java class with the detection login. The default `GenericSecretDetector` is sufficient, allowing for _purely declarative logic_ for the detection of the leak and its verification. Simply follow the instructions in the `$SCANNER_DIR/onf/secrets/_template.yml_` that you may use as the base for your detector. You simply need to specify patterns to match for the entry key / value or source file, with pre-defined patterns and options for additional checks.

For example, a GitLab Personal Access Token detector might be as simple as this:

```yaml
id: custom_gitlab_token
enabled: yes
type: gitlab_token
description: GitLab Personal Access Token
severity: critical

value:
  regex:
    # GitLab personal tokens start with 'glpat-' 
    # followed by 20 up to 22 alphanumeric characters and some separators
    pattern: '\bglpat-[0-9a-zA-Z\-=_]{20,22}\b'
```

Adding a verifier allows to check if the secret is active, reducing the rate of false positives:

```yaml
# Verifier invokes /api/v4/user with the token,
# and checks for 200 or 403 HTTP codes
#
# If the token is invalid, sets severity=info (no risk now)
# bit it is sent so the user may investigate past accesses with the token
verifier:
  className: io.xygeni.extensions.custom_detectors.secrets.verifier.ApiVerifier
  action: set_info_when_not_verified
  properties:
    host: gitlab.com/api/v4/user
    tokenPrefix: Bearer
    httpCodes: [200, 403]
```

## Implementing a Detector Class

For more complex cases, a Java class with the detection logic can be developed. A defector must implement the `void detect(Entry e, SecretsContext ctx)` method and may overwrite lifecycle methods, with the following `SecretDetector` interface:

```java
public interface SecretDetector {
  /** Called when instantiated */
  void configure(DetectorConfig detectorConfig, SecretsConfig secretsConfig);

  /** Called on engine start, before processing files */
  default void initialize(SecretsContext ctx) throws DetectorInitException {}

  /**
   * If true, this detector is valid for the given file (path and inferred type).
   */
  default boolean accept(String path, FileType type) { return true; }

  /** Called on each Entry extracted by the matching parser */
  void detect(Entry e, SecretsContext ctx) throws DetectorException;

  /** Called on engine end, after files processed */
  default void terminate(SecretsContext ctx) throws DetectorInitException {}
}
```

Actual implementations often derive from `GenericSecretDetector` or `BaseSecretDetector` base classes, which provide default implementations and helper methods for creating and reporting `PotentialSecret`.


Verifiers for credentials such as access tokens or API keys often call an API endpoint with the credential, and check the response to determine if the credential is valid. Local commands and other mechanisms may be used to verify if the credential is valid.

The following examples for secret detectors are provided to illustrate different implementation alternatives:

## Examples

### Docker Authentication
This is a simple example of purely declarative detector, with the following [YAML configuration](../src/main/resources/secrets/custom_dockercfg.yml):

```yaml
#
# Example of custom detector configuration for .dockercfg
#
id: custom_dockercfg
enabled: yes
type: dockercfg

description: Hardcoded .dockercfg auth

severity: critical

# Auth is coded in a docker configuration file
fileTypes:
  - dockercfg
  - json
fileRegex: '(\.dockercfg|\.docker/config\.json)$'

# Key is 'auth'
key:
  regex:
    pattern: 'auth'
    exact: yes
    ignorecase: no

# .dockercfg auth is base64 encoded
value:
  base64: yes
  ascii: yes
  minlen: 1
```

This matches the `auth` key (base64-encoded) in the `.dockercfg` or `.docker/config.json` files.

### GitLab Personal Access Token

A detector for a Gitlab Personal Access Token has the following [YAML configuration](../src/main/resources/secrets/custom_gitlab_token.yml):

```yaml
# Example of custom detector configuration for GitLab Personal Access Token
# This checks for a GitLab Personal Access Token, which has a 'glpat-' prefix.
# The verifier uses the '/api/v4/user' endpoint with the token to verify.

id: custom_gitlab_token
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
  className: io.xygeni.extensions.custom_detectors.secrets.verifier.ApiVerifier
  action: set_info_when_not_verified
  properties:
    host: gitlab.com/api/v4/user
    tokenPrefix: Bearer
    httpCodes: [200, 403]
```

### Xygeni Token
For verification of [Xygeni.io tokens](https://docs.xygeni.io/xygeni-administration/platform-administration/profile#generate_token_for_scanner-1), a detector with the following [YAML configuration](../src/main/resources/secrets/custom_xygeni_token.yml):

```yaml
# Example of custom detector configuration for Xygeni.io token,
# which is a JWT token with 'xya_' prefix.
# XygeniJwtDetector extends JwtDetector, which removes the prefix and implements isValidToken(JWT).
#
# It also provides a Verifier that checks if the secret encodes a Xygeni JSON Web Token.
id: custom_xygeni_token
enabled: yes
type: jwt
description: Xygeni.io Token
severity: high
confidence: high
classname: io.xygeni.extensions.custom_detectors.secrets.XygeniJwtDetector

verifier:
  className: io.xygeni.extensions.custom_detectors.secrets.verifier.XygeniJwtVerifier
  # action: do_nothing | increase_severity_when_verified | decrease_severity_when_not_verified | set_info_when_not_verified |ignore_when_not_verified
  action: set_info_when_not_verified

value:
  regex:
    pattern: 'xya_eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
    ignorecase: yes
    exact: false
  minEntropy: 3
```

The [XygeniJwtVerifier](../src/main/java/io/xygeni/extensions/custom_detectors/secrets/verifier/XygeniJwtVerifier.java) checks if the JSON Web Token is syntactically valid and has not expired,
and also that the token is active and not revoked.