package io.xygeni.extensions.custom_detectors.sast.test.assertions;

import java.io.File;
import java.util.List;

/**
 * IssueCommentsExtractor - Interface for extracting expected issues from source code comments.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public interface IssueCommentsExtractor {

  List<IssueComment> issues(File file);
}
