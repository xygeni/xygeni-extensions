package io.xygeni.extensions.custom_detectors.sast.test.assertions;

import com.depsdoctor.commons.file.FileType;
import com.depsdoctor.commons.file.FileTypeHelper;
import com.depsdoctor.commons.io.Files;
import com.depsdoctor.commons.io.IO;
import com.depsdoctor.core.utils.CommentsHelper;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.depsdoctor.commons.Strings.hasText;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Fail.fail;

/**
 * BaseIssueCommentsExtractor - Extracts the expected issues from the source code.
 * <br>
 * Issues should be marked as FLAW or ISSUE. A quantifier (xN, like x2) may be added when more than one issue is expected in the
 * same line.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class BaseIssueCommentsExtractor implements IssueCommentsExtractor {

  private static final Pattern FLAW_PATTERN = Pattern.compile("(ISSUE|FLAW)\\s*(x([0-9]+))?");
  private static final Pattern EXPLAIN_PATTERN = Pattern.compile("explain='([^']*)'");
  private static final Pattern EXPLAIN_CONTAINS_PATTERN = Pattern.compile("explain\\.contains='([^']*)'");
  private static final Pattern CWE_PATTERN = Pattern.compile("cwe='(\\S+(,\\S+)*)'");

  public List<IssueComment> issues(File file) {
    try {
      var contents = IO.slurp(file);
      assertThat(contents).isNotNull();

      List<IssueComment> issueComments = new ArrayList<>();
      var ft = FileTypeHelper.fileType(file);
      if (ft == FileType.config && file.getName().contains(".")) {
        var ext = Files.getExtension(file);
        ft = FileTypeHelper.fileType(ext);
      }

      var lines = contents.lines().collect(Collectors.toList());
      for(int i = 0; i < lines.size(); i++) {
        var currentLine = lines.get(i);
        if(!isIssueComment(currentLine, ft)) continue;

        for(int issueNumber = 0; issueNumber < countIssuesInLine(currentLine); issueNumber++) {
          var line = CommentsHelper.inSameLine(ft)? i + 1 : i + 2; // comments on the previous lines
          var explain = extractExplain(currentLine);
          var explainContains = extractExplainContains(currentLine);
          Set<String> cwes = extractCwes(currentLine);
          var issueComment = new IssueComment(line, explain, explainContains, cwes);
          issueComments.add(issueComment);
        }
      }

      return issueComments;

    } catch (IOException e) {
      fail("An exception was thrown while extracting the issues: " + e.getMessage());
    }

    return null;
  }

  // IMPLEMENTATION
  private boolean isIssueComment(String currentLine, FileType ft) {
    if(!CommentsHelper.isComment(currentLine, ft) && !CommentsHelper.isPartialLineComment(currentLine, ft)) return false;

    return FLAW_PATTERN.matcher(currentLine).find();
  }

  private int countIssuesInLine(String currentLine) {
    var matcher = FLAW_PATTERN.matcher(currentLine);
    if(matcher.find()) {
      var occurrences = matcher.group(3);
      return hasText(occurrences)? Integer.parseInt(occurrences) : 1;
    }

    return 1;
  }

  private String extractExplain(String currentLine) {
    var matcher = EXPLAIN_PATTERN.matcher(currentLine);
    if(!matcher.find()) return null;

    return matcher.group(1);
  }

  private String extractExplainContains(String currentLine) {
    var matcher = EXPLAIN_CONTAINS_PATTERN.matcher(currentLine);
    if(!matcher.find()) return null;

    return matcher.group(1);
  }

  private Set<String> extractCwes(String currentLine) {
    var matcher = CWE_PATTERN.matcher(currentLine);
    if(!matcher.find()) return null;

    return Arrays.stream(matcher.group(1).split(","))
        .sequential()
        .collect(Collectors.toSet());
  }
}
