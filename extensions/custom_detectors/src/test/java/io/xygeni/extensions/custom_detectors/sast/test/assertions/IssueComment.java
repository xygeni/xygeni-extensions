package io.xygeni.extensions.custom_detectors.sast.test.assertions;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Set;

/**
 * IssueComment - Data class representing an expected issue extracted from source code comments.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
@RequiredArgsConstructor
@Getter
public class IssueComment {

  private final int line;
  private final String explanation;
  private final String explanationContains;
  private final Set<String> cwes;

  public IssueComment(int line) {
    this.line = line;
    this.explanation = null;
    this.explanationContains = null;
    this.cwes = null;
  }
}
