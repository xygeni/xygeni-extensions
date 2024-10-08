# Secrets Leak Detector

The [Secrets Scanner](https://docs.xygeni.io/xygeni-products/secrets-security/secrets-scanner) detects potential hard-coded secrets in source code and in other places, such as commits in git history or container images.

The secrets engine traverses all files of a filesystem directory, or alternatively from file changes in commits from the git history, or from layers in a container image tarball. Each file seen is tokenized or parsed accordingly to its type, and key-value pairs potentially holding hardcoded secrets are extracted in an `Entry` object. For each entry, enabled detectors run, typically looking for patterns in the key or the value for each specific type of secret. When a potential secret is found, it is reported as a potential leak, by creating a `PotentialSecret` object that it is added to the findings in the `SecretsContext`.

A detector may include a **verifier** that could check if the potential secret found is indeed active, to reduce the rate of false positives, and a **remediator** for fully automatic or user-controlled remediation (typically to revoke, rotate or deactivate a leaked credential, when possible and convenient).

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
verifier:
  className: io.xygeni.extensions.custom_detectors.secrets.verifier.GitlabVerifier
  action: set_info_when_not_verified
  properties:
    host: gitlab.com/api/v4/user
    tokenPrefix: Bearer
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
# The verifier uses the 'gitlab.com/api/v4/user' endpoint with the token to verify as the bearer token.

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
  className: io.xygeni.extensions.custom_detectors.secrets.verifier.GitlabVerifier
  # action: do_nothing | increase_severity_when_verified | decrease_severity_when_not_verified | set_info_when_not_verified | ignore_when_not_verified
  action: set_info_when_not_verified
  properties:
    host: gitlab.com/api/v4/user
    tokenPrefix: Bearer
```

This includes a [verifier](../src/main/java/io/xygeni/extensions/custom_detectors/secrets/verifier/GitlabVerifier.java) that checks if the token is valid. The mechanism is to call the Gitlab API endpoint `/api/v4/user` with the token as the bearer token, to test if the token is valid. The API returns 200 for a valid token and 403 for a valid token but not the right scope. Only 401 is returned for an invalid token.

```java
public class GitlabVerifier extends ApiVerifier {
  @Override
  protected boolean verifyStatus(Response<String> res) {
    int code = res.statusCode();
    switch (code) {
      case HttpURLConnection.HTTP_OK: // 200: good PAT, read_user scope
      case HttpURLConnection.HTTP_FORBIDDEN:  // 403: good PAT, but not the right scope
        return true;
      case HttpURLConnection.HTTP_UNAUTHORIZED: // 401: bad PAT
        return false;
    }
    return false;
  }
}
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