package io.xygeni.extensions.custom_detectors.sast.java;

import io.xygeni.sast.scanner.detector.java.JavaTaintingRule;

/**
 * CustomSqlInjection - Detects SQL injection vulnerabilities
 * by tracking tainted data from sources (user input) to sinks (SQL queries).
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class CustomSqlInjection extends JavaTaintingRule {
  // Empty class - all configuration via YAML
  // Override methods only if custom behavior is needed
}
