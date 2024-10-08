package io.xygeni.extensions.custom_detectors.secrets.verifier;

import com.depsdoctor.commons.TriState;
import com.depsdoctor.depsscanner.services.HttpClient;
import com.depsdoctor.depsscanner.services.exception.ServiceException;
import com.depsdoctor.depsscanner.services.exception.TimeoutException;
import com.depsdoctor.secrets.scanner.detector.verifier.JwtVerifier;
import okhttp3.Request;

import java.net.HttpURLConnection;
import java.util.Map;

import static com.depsdoctor.commons.config.ApiConfig.APIKEY_PREFIX;

/**
 * XygeniJwtVerifier checks if the secret encodes a Xygeni JSON Web Token.
 * <p>
 * Basically removes the Xygeni.io JWT Prefix and then invokes
 * the base {@code JwtVerifier.verify()} logic to perform the actual verification.
 * <p>
 * The JwtVerifier verifies syntax for JWT token and expiration, as well as signature verification
 * (for signature schemes that do not need a cryptographic key).
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class XygeniJwtVerifier extends JwtVerifier {

  @Override protected TriState verify(String token) {
    if(!token.startsWith(APIKEY_PREFIX)) return TriState.FALSE;
    String jwtToken = token.substring(APIKEY_PREFIX.length());
    TriState result = super.verify(jwtToken); // validate JWT expiration
    if(result.isTrue()) {
      // additionally check with /user/current API
      result = UserApi.isValidToken(token);
    }
    return result;
  }

  @SuppressWarnings("rawtypes")
  private static class UserApi extends HttpClient<Map> {

    public static TriState isValidToken(String token) {
      try(var api = new UserApi()) {
        String url = api.concat(api.getBaseUrl(), "/user/current");
        var req = new Request.Builder().url(url)
          .header("Authorization", "Bearer " + token)
          .get().build();
        var res = api.send(req, Map.class);
        if(res != null && res.statusCode() == HttpURLConnection.HTTP_OK && res.getResult().containsKey("login")) {
          return TriState.TRUE;
        }
        if(api.isUnauthorized(res) || api.isForbidden(res)) return TriState.FALSE;
        return TriState.UNKNOWN;

      } catch (ServiceException | TimeoutException e) {
        return TriState.UNKNOWN;
      }
    }
  }

}
