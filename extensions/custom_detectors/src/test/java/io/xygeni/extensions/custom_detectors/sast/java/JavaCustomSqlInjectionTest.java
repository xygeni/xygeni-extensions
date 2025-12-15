package io.xygeni.extensions.custom_detectors.sast.java;

import io.xygeni.sast.scanner.engine.SastContext;
import io.xygeni.extensions.custom_detectors.sast.test.assertions.SastAssertions;
import org.junit.jupiter.api.Test;

import java.io.File;

import static io.xygeni.extensions.custom_detectors.sast.java.JavaTestHelper.runJava;
import static io.xygeni.extensions.custom_detectors.sast.test.helpers.SastDetectorTestHelper.dump;

/**
 * JavaCustomSqlInjectionTest - Unit tests for custom_sql_injection detector.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class JavaCustomSqlInjectionTest {
  private static final String ID = "custom_sql_injection";


  @Test
  public void testRegression() {
    SastContext ctx = runJava(ID, "regression");
    dump(ctx);
    SastAssertions.assertThat(ctx).matchesIssues();
  }
}
