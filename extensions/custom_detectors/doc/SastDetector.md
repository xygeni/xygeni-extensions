# Developing Custom SAST Detectors

## Introduction

This guide explains how to create a custom SAST (Static Application Security Testing) detector for finding security vulnerabilities in source code. SAST detectors (also called "rules") analyze code patterns and data flows to identify potential security issues.

Custom detectors must be implemented in a Java class, that analyze AST nodes for the parsed input and, alternatively, function calls and field dereferences. Configuration files can be also analyzed for flaws. 

Detectors may also check for data-flow from sources (externally controlled inputs) to sinks (access to resources of interest), so when a non-neutralized path between relevant source and sink is found, an injection vulnerability is reported. Such detector use an inter-procedural tainting propagation algorithm and for that reason is known as 'Tainting Detector'. Tainting detectors are defined mostly by declaring the relevant kinds of source, sink and neutralization sites in the detector descriptor. 

In what follows: 

- 'Rule' is a synonym for a SAST detector.
- `LANG` refers to the language name (e.g., `csharp`, `go`, `java`, `javascript`, `kotlin`, `php`, `python`, `swift`)
- `DETECTOR_ID` refers to the detector identifier (e.g., `custom_avoid_native_calls`, `custom_sql_injection`)
- `$PROJECT_DIR` refers to the path to this Maven project (`extensions/custom_detectors`)
- `$SCANNER_DIR` refers to the path where the Xygeni scanner is installed

## Detector Types

There are two main types of SAST detectors:

### Regular Detectors

**Base class:** `LANGRule` (which extends `BaseSastRule`)

Regular detectors analyze code patterns, API usage, and configuration issues. They are suitable for:

- **Configuration mismatches**: Missing security controls (CSRF protection, secure cookies)
- **Cryptography issues**: Weak encryption/hash algorithms, weak random number generation, hardcoded keys, insufficient key sizes
- **Framework vulnerabilities**: Framework-specific security flaws
- **Dangerous API usage**: Calls to risky functions
- **Code smells**: Race conditions, infinite loops, information exposure

Implementation pattern:

```java
public class MyDetector extends JavaRule {
  @Override
  protected void checkCall(JavaCallSignature call, SastContext ctx) {
    // Check method calls
    if (isDangerousFunction(call)) {
      createIssue(call, ctx, "Message with {0}", argument);
    }
  }

  @Override
  protected void checkNode(JavaNode node, SastContext ctx) {
    // Check any AST node
    if (isDangerousConstruct(node)) {
      createIssue(node, ctx, "Dangerous construct found");
    }
  }
}
```

The `checkCall()` method is the most common extension point, invoked for each method/function call in the analyzed code. From the `call` parameter you can access: the function descriptor via `call.getFunctionDescriptor()` (which provides metadata tags, container class, and parameter types), arguments by position via `call.getArgument(index)` or by name via `call.getNamedArg("name")`, and the target object type via `call.getAccessedType()`. Use function descriptor tags from metadata (e.g., `fd.anyTag("dangerous")`) to identify functions of interest, then analyze argument values using `getEvaluator().evalString(arg)` to detect hardcoded values or unsafe patterns.

The `scan()` method can be overridden when you need custom AST traversal beyond call analysis. Override `scan()` to analyze class structures, field declarations, or modifiers (e.g., detecting serializable classes with sensitive fields). You may also override it to maintain state across multiple visits (initialize a cache before calling `super.scan()`, then clean up afterward) or to implement two-pass analysis by implementing the `PreScanAstTask` interface and using `preScan()` to register sinks before the main analysis pass.

The `configure()` method reads properties from the YAML descriptor to customize detector behavior. Always call `super.configure(dc, sc)` first, then use `dc.getProperty("name", defaultValue)` to read booleans, strings, lists, or maps. Common uses include reading whitelist/blacklist patterns, threshold values, or regex patterns that are compiled during configuration. If configuration is invalid, call `setEnabled(false)` to disable the detector gracefully.


### Tainting Detectors

**Base class:** `LANGTaintingRule` extends `BaseTaintingRule`

Tainting detectors perform data-flow analysis to track tainted data from sources (user input) to sinks (dangerous operations). They are ideal for:

- **Injection vulnerabilities**: SQL injection, command injection, LDAP injection ...
- **Cross-site scripting (XSS)**: Unescaped user input in HTML/JavaScript
- **Path traversal**: File system access with untrusted paths
- **Server-side request forgery (SSRF)**: HTTP requests with user-controlled URLs
- **XML external entity (XXE)**: XML parsing with external entities enabled

**Implementation pattern:**

Tainting rules typically don't need custom Java code - they are configured via YAML with sources, sinks, and neutralizations:

```yaml
classname: java.JavaTaintingRule

properties:
  sources:
    - external_input
    - user_input
  sinks:
    - sql_injection
  neutralizations:
    - sql_injection
    - hash
```

If custom behavior is needed, typically for filtering or confirming sinks, extend the base tainting detector:

```java
public class CustomSqlInjection extends JavaTaintingRule {
  // Override methods only if custom behavior is needed
}
```

Common reasons for overriding methods in tainting rules include: filtering sinks to specific contexts (e.g., XSS rules filter to web contexts only via `filterSink()`), adding custom sink checkers for vulnerability-specific patterns via `getAdditionalSinkCheckers()` (e.g., detecting sensitive cookie names or unsafe comparison operations), reducing false positives by analyzing content types or framework-specific annotations via `filterIssue()`, and implementing dynamic neutralization detection for validation patterns that cannot be expressed through metadata alone (e.g., range checks for array index validation via `getDynamicNeutralizationCheckers()`).

## Creating a Custom Detector

### 1. Create the Java Detector Class (Optional for Tainting Rules)

Location: `$PROJECT_DIR/src/main/java/io/xygeni/extensions/custom_detectors/sast/LANG/DetectorName.java`

**For a regular detector:**

```java
package io.xygeni.extensions.custom_detectors.sast.java;

import com.depsdoctor.core.model.sast.SastRule;
import io.xygeni.sankxy.java.expr.chain.JavaCallSignature;
import io.xygeni.sast.scanner.config.SastScanConfig;
import io.xygeni.sast.scanner.detector.java.JavaRule;
import io.xygeni.sast.scanner.engine.SastContext;

/**
 * CustomMyDetector - Description of what this detector does.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class CustomMyDetector extends JavaRule {

  @Override
  public void configure(SastRule dc, SastScanConfig sc) {
    super.configure(dc, sc);
    // Initialize custom properties from YAML configuration
  }

  @Override
  protected void checkCall(JavaCallSignature call, SastContext ctx) {
    if (isVulnerableCall(call)) {
      createIssue(ctx, call.getNode());
    }
  }

  private boolean isVulnerableCall(JavaCallSignature call) {
    // Your detection logic here
    return false;
  }
}
```

**For a tainting detector (only if custom behavior is needed):**

```java
package io.xygeni.extensions.custom_detectors.sast.java;

import io.xygeni.sast.scanner.detector.java.JavaTaintingRule;

/**
 * CustomSqlInjection - Custom SQL injection detector.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class CustomSqlInjection extends JavaTaintingRule {
  // Empty class - all configuration via YAML
  // Override methods only if custom behavior is needed
}
```



### 2. Create the YAML Configuration

Location: `$PROJECT_DIR/src/main/resources/sast/LANG/LANG.custom_detector_id.yml`

```yaml
id: java.custom_detector_id

enabled: yes

# Detector kind: cryptography, injection, xss, authentication, authorization, etc.
kind: api

# Severity: critical, high, medium, low, info
severity: high

description: Brief description of the vulnerability

# Java class path (relative to io.xygeni.sast.scanner.detector.LANG)
# Use the custom extensions package for custom detectors
classname: io.xygeni.extensions.custom_detectors.sast.java.CustomMyDetector

# Optional configuration properties
properties:
  # Custom thresholds, patterns, etc.
  allowedMethods: []

# CWE and compliance mappings
tag: [CWE:123, NIST.SP.800-53, PCI-DSS:6.5.1]

# Security policies that include this detector. Ignore for custom detectors.
defaultPolicies:
  - Very_Strict
```

**Key fields:**

- `id`: Unique identifier in format `LANG.custom_detector_id`
- `enabled`: Whether the detector is enabled by default
- `kind`: Category of vulnerability (api, injection, cryptography, misconfiguration, etc.)
- `severity`: Risk level (critical/high/medium/low/info)
- `classname`: Full Java class path for custom detectors
- `tag`: CWE IDs and compliance framework mappings

HINT: You may start with [_template.yml_](../src/main/resources/sast/_template.yml_) or [_template_tainting.yml_](../src/main/resources/sast/_template_tainting.yml_) as templates for creating the descriptor.

HINT: [xygeni_sast_descriptor.schema.json](../src/main/resources/sast/xygeni_sast_descriptor.schema.json) is the schema that could register in your IDE for auto-completion assistance.

### 3. Create the AsciiDoc Documentation (Optional)

It is recommended to document your detector following the same structure as Xygeni standard detectors.

Location: `$PROJECT_DIR/src/main/doc/asciidoc/sast/LANG/LANG.custom_detector_id.adoc`

```asciidoc
= Detector Title
:icons: font
:toc: left

[cols="1,3" width="50%" frame="ends" grid="rows" stripes="odd" options=noheader]
|===
|ID | java.custom_detector_id
|Severity | [red]#high#
|Resource | Api
|Language | Java
|===

== Description

Brief description of what this detector finds.

== Rationale

Explanation of why this is a security issue and the potential impact.

[source,java]
----
// Vulnerable code example
public void vulnerableMethod() {
    dangerousFunction(userInput); // FLAW
}
----

== Remediation

Steps to fix the vulnerability.

[source,java]
----
// Secure code example
public void secureMethod() {
    safeFunction(sanitize(userInput)); // FIXED
}
----

== Configuration

The detector has the following configurable parameters:

- `allowedMethods`: List of methods that are allowed by this detector.

== References

- https://cwe.mitre.org/data/definitions/123.html[CWE-123]: Description
```

HINT: You may base your detector's documentation on [template.adoc_](../src/main/doc/asciidoc/sast/template.adoc_).

### 4. Create the Test Class

Location: `$PROJECT_DIR/src/test/java/io/xygeni/extensions/custom_detectors/sast/LANG/LANGCustomDetectorNameTest.java`

The test class 

```java
package io.xygeni.extensions.custom_detectors.sast.java;

import io.xygeni.sast.scanner.engine.SastContext;
import io.xygeni.sast.scanner.test.assertions.SastAssertions;
import org.junit.jupiter.api.Test;

import java.io.File;

import static io.xygeni.sast.scanner.test.helpers.JavaTestHelper.runJava;

public class JavaCustomMyDetectorTest {
  private static final String DETECTOR_ID = "custom_detector_id";
  private static final File DETECTOR_DIR =
    new File("src/test/resources/detector/java/custom_detector_id");

  @Test
  public void testRegression() {
    var file = new File(DETECTOR_DIR, "regression");
    SastContext ctx = runJava(file, DETECTOR_ID);

    // Automatically matches against expected issues
    SastAssertions.assertThat(ctx).matchesIssues();
  }
}
```

### 5. Create Test Resources

Location: `$PROJECT_DIR/src/test/resources/detector/LANG/custom_detector_id/regression/`

Create test files with code examples that should trigger the detector:

**Example: `Vulnerable.java`**

```java
public class Vulnerable {
    public void method() {
        // This call is vulnerable
        dangerousFunction(userInput); // FLAW
    }
}
```

The comment `// FLAW` tells the test framework that an issue is expected on that line.

**Example: `Secure.java`**

```java
public class Secure {
    public void method() {
        // No issue expected - this is the secure way
        safeFunction(sanitize(userInput));
    }
}
```

## Deploying and Testing

### Build and Deploy

```bash
cd extensions/custom_detectors
mvn install -Dxygeni.home=$XYGENI_DIR -Dxygeni.version=x.y.z
```

This will:
1. Compile the Java classes
2. Copy YAML configurations to `$XYGENI_DIR/conf.custom/sast/LANG/`
3. Copy the JAR to `$XYGENI_DIR/lib.custom/`

### Run Tests

```bash
# Run all tests for your detector
mvn test -Dtest=JavaCustomMyDetectorTest

# Run specific test method
mvn test -Dtest=JavaCustomMyDetectorTest#testRegression
```

### Test with the Scanner

```bash
xygeni sast --detectors=java.custom_detector_id <target>
```

### Upload to Platform

```bash
xygeni util conf-upload
```

## Examples

This project includes example detectors for reference:

### Java Regular Detector: CustomAvoidNativeCalls

Detects calls to native methods (JNI), which can introduce security risks.

- Class: `io.xygeni.extensions.custom_detectors.sast.java.CustomAvoidNativeCalls`
- YAML: `src/main/resources/sast/java/java.custom_avoid_native_calls.yml`
- Documentation: `src/main/doc/asciidoc/sast/java/java.custom_avoid_native_calls.adoc`

### Java Tainting Detector: CustomSqlInjection

Detects SQL injection vulnerabilities using data-flow analysis.

- Class: `io.xygeni.extensions.custom_detectors.sast.java.CustomSqlInjection`
- YAML: `src/main/resources/sast/java/java.custom_sql_injection.yml`
- Documentation: `src/main/doc/asciidoc/sast/java/java.custom_sql_injection.adoc`

### C# Regular Detector: CustomDangerousApi

Detects use of dangerous APIs like BinaryFormatter.

- Class: `io.xygeni.extensions.custom_detectors.sast.csharp.CustomDangerousApi`
- YAML: `src/main/resources/sast/csharp/csharp.custom_dangerous_api.yml`
- Documentation: `src/main/doc/asciidoc/sast/csharp/csharp.custom_dangerous_api.adoc`

### C# Tainting Detector: CustomCommandInjection

Detects command injection vulnerabilities.

- Class: `io.xygeni.extensions.custom_detectors.sast.csharp.CustomCommandInjection`
- YAML: `src/main/resources/sast/csharp/csharp.custom_command_injection.yml`
- Documentation: `src/main/doc/asciidoc/sast/csharp/csharp.custom_command_injection.adoc`

### Python Framework Detector: CustomDjangoUnsafeSessionConfiguration

Detects unsafe session configuration in Django applications.

- Class: `io.xygeni.extensions.custom_detectors.sast.python.CustomDjangoUnsafeSessionConfiguration`
- YAML: `src/main/resources/sast/python/python.custom_django_unsafe_session_configuration.yml`
- Documentation: `src/main/doc/asciidoc/sast/python/python.custom_django_unsafe_session_configuration.adoc`

## Checklist

Before deploying your detector:

- [ ] Java detector class extends correct base class (`LANGRule` or `LANGTaintingRule`)
- [ ] YAML configuration file with correct `id`, `classname`, and `tag` fields
- [ ] AsciiDoc documentation with Description, Rationale, Remediation, Configuration, and References sections
- [ ] Test class with at least one regression test
- [ ] Test resources in `regression/` directory with `// FLAW` markers
- [ ] All tests pass: `mvn test -Dtest=YourDetectorTest`

## Common Pitfalls

- **Forgetting CWE tags**: Always include relevant CWE IDs in the `tag` field
- **Wrong classname path**: Use the full package path for custom detectors in xygeni-extensions
- **Missing test markers**: Use `// FLAW` comments in test files to mark expected issues
- **Not calling super.configure()**: Always call `super.configure(dc, sc)` when overriding the configure method
- **Parsing errors**: Make sure that test files have valid syntax for the language