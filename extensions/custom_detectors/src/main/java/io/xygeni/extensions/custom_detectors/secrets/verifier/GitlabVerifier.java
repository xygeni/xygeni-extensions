package io.xygeni.extensions.custom_detectors.secrets.verifier;

import com.depsdoctor.depsscanner.services.Response;
import com.depsdoctor.secrets.scanner.detector.verifier.ApiVerifier;

import java.net.HttpURLConnection;

/**
 * GitlabVerifier - Verifier for Gitlab v2 PATs.
 * <p>
 * It needs to overload the {@code verifyStatus(Response)} method of the {@code ApiVerifier},
 * because the Gitlab API returns 200 for a valid PAT, and 403 for a valid PAT but not the right scope scope.
 * Only 401 is returned for an invalid PAT.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class GitlabVerifier extends ApiVerifier {

  /** This simply takes http code 200 or 403 for valid token, and 401 for invalid. */
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
