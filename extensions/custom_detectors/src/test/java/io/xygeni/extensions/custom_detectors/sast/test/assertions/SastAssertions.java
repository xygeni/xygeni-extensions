package io.xygeni.extensions.custom_detectors.sast.test.assertions;

import com.depsdoctor.core.model.sast.CodeVulnerabilities;
import com.depsdoctor.core.model.sast.SastReport;
import io.xygeni.sast.scanner.engine.SastContext;

import java.io.File;

/**
 * SastAssertions - Factory class for creating SAST assertions.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class SastAssertions {

  public static SastAssertion assertThat(SastContext ctx) {
    return assertThat(ctx.codeVulnerabilities(), ctx.getDirectory());
  }

  public static SastAssertion assertThat(SastReport report) {
    return assertThat(report.getVulnerabilities(), report.getMetadata().getDirectory());
  }

  public static SastAssertion assertThat(CodeVulnerabilities codeVulnerabilities, File basedir) {
    return new SastAssertion(codeVulnerabilities, basedir);
  }
}
