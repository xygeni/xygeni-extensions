package io.xygeni.extensions.custom_detectors.sast.csharp;

import io.xygeni.sast.scanner.detector.csharp.CSharpTaintingRule;

/**
 * CustomCommandInjection - Detects command injection vulnerabilities
 * by tracking tainted data from sources (user input) to sinks (process execution).
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class CustomCommandInjection extends CSharpTaintingRule {
  // Empty class - all configuration via YAML
  // Override methods only if custom behavior is needed
}
