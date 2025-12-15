package io.xygeni.extensions.custom_detectors.sast.test.assertions;

import com.depsdoctor.commons.io.Files;
import com.depsdoctor.core.model.sast.CodeVulnerabilities;
import com.depsdoctor.core.model.sast.CodeVulnerability;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.assertj.core.api.SoftAssertions;

import java.io.File;
import java.text.MessageFormat;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.depsdoctor.commons.Strings.hasText;
import static io.xygeni.extensions.custom_detectors.sast.test.helpers.SastDetectorTestHelper.listFiles;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * SastAssertion - Assertion class for validating SAST scan results.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
@RequiredArgsConstructor
public class SastAssertion {

  private final CodeVulnerabilities codeVulnerabilities;
  private final File basedir;

  public SastAssertion hasIssues(int expected) {
    assertThat(codeVulnerabilities.size())
        .as("Not same issues number: %d expected but %d found", expected, codeVulnerabilities.size())
        .isEqualTo(expected);
    return this;
  }

  public SastAssertion inLines(int... lines) {
    var foundLines = codeVulnerabilities.stream().map(CodeVulnerability::getBeginLine).sorted().collect(Collectors.toList());
    var expected = Arrays.stream(lines).boxed().collect(Collectors.toList());

    assertThat(foundLines)
        .as("Not same lines: %s expected but %s found", expected, foundLines)
        .isEqualTo(expected);
    return this;
  }

  public SastAssertion hasNoIssues() { return hasIssues(0); }

  /**
   * Match issues annotated via comments in source code.
   */
  public SastAssertion matchesIssues() {
    var extractor = new BaseIssueCommentsExtractor();
    return matchesIssues(extractor);
  }

  public SastAssertion matchesIssues(IssueCommentsExtractor extractor) {
    var files = listFiles(basedir);
    return matchesIssues(extractor, files);
  }

  // IMPLEMENTATION
  public SastAssertion matchesIssues(IssueCommentsExtractor extractor, Stream<File> analyzedFiles) {
    SoftAssertions softAssertions = new SoftAssertions();

    for(var file : analyzedFiles.collect(Collectors.toSet())) {
      var expectedIssues = extractor.issues(file);
      var expectedLines = expectedIssues.stream()
          .map(IssueComment::getLine)
          .collect(Collectors.toList());

      var relativePath = Files.relativize(file, basedir);
      var fileIssues = codeVulnerabilities.getVulnerabilities().stream()
          .filter(issue -> issue.getFile().equals(relativePath))
          .collect(Collectors.toSet());
      var fileIssuesLines = fileIssues.stream()
          .flatMap(issue -> {
            if (issue.getCodeFlows() == null || issue.getCodeFlows().isEmpty()) {
              return Stream.of(issue.getBeginLine());
            }

            return issue.getCodeFlows().stream()
                .map(cf -> cf.getSink().getLine());

          })
          .sorted().collect(Collectors.toList());

      Collections.sort(expectedLines);

      var missing = new ArrayList<>(expectedLines);
      missing.removeAll(fileIssuesLines);

      var notExpected = new ArrayList<>(fileIssuesLines);
      notExpected.removeAll(expectedLines);

      var explain = "";
      if (!missing.isEmpty()) {
        explain = "\nMissing issue lines (FNs) are: " +
            missing.stream().map(Object::toString).collect(Collectors.joining(","));
      }
      if (!notExpected.isEmpty()) {
        explain += "\nNot expected issue lines (FPs) are: " +
            notExpected.stream().map(Object::toString).collect(Collectors.joining(","));
      }

      var msg = MessageFormat.format(
          "In file: {0} -> Expected issue lines: {1} do not match: {2}. {3}",
          relativePath, expectedLines, fileIssuesLines, explain
      );
      softAssertions.assertThat(fileIssuesLines)
          .withFailMessage(msg).
          isEqualTo(expectedLines);

      assertExtraInfo(fileIssues, expectedIssues, relativePath, softAssertions);
    }

    softAssertions.assertAll();

    return this;
  }

  private void assertExtraInfo(
      @NonNull Set<CodeVulnerability> issues, List<IssueComment> expectedIssues, String relativePath,
      SoftAssertions softAssertions
  ) {
    for(var expectedIssue : expectedIssues) {
      var issue = issues.stream().filter(i -> i.getBeginLine() == expectedIssue.getLine()).findFirst().orElse(null);
      if(issue == null) continue; // should not happen at this point

      var issueLine = issue.getBeginLine();
      var issueExplain = issue.getExplanation();
      if(hasText(issueExplain)) {
        if(hasText(expectedIssue.getExplanation())) {
          var msg = MessageFormat.format(
              "In file: {0} -> Explanation for issue at line: {1} - ''{2}'' do not match: ''{3}''",
              relativePath, issueLine, issueExplain, expectedIssue.getExplanation()
          );
          softAssertions.assertThat(expectedIssue.getExplanation())
              .withFailMessage(msg).
              isEqualTo(issueExplain);

        } else if(hasText(expectedIssue.getExplanationContains())) {
          var msg = MessageFormat.format(
              "In file: {0} -> Explanation for issue at line: {1} - ''{2}'' do not contains: ''{3}''",
              relativePath, issueLine, issueExplain, expectedIssue.getExplanationContains()
          );
          softAssertions.assertThat(issueExplain)
              .withFailMessage(msg).
              contains(expectedIssue.getExplanationContains());
        }
      }

      var issueCwes = issue.getCwes();
      if(issueCwes != null && expectedIssue.getCwes() != null) {
        // clean CWEs and keep just the code
        issueCwes = issueCwes.stream()
            .map(cwe -> !cwe.contains("CWE-")? cwe : cwe.substring(4))
            .collect(Collectors.toSet());

        var msg = MessageFormat.format(
            "In file: {0} -> CWEs for issue at line: {1} - {2} do not match: {3}",
            relativePath, issueLine, issueCwes, expectedIssue.getCwes()
        );
        softAssertions.assertThat(expectedIssue.getCwes())
            .withFailMessage(msg).
            containsExactlyInAnyOrderElementsOf(issueCwes);
      }
    }
  }
}
