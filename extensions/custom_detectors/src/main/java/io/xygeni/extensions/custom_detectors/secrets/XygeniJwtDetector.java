package io.xygeni.extensions.custom_detectors.secrets;

import com.depsdoctor.core.utils.jwt.JWT;
import com.depsdoctor.secrets.scanner.detector.impl.JwtDetector;
import org.json.JSONObject;

import static com.depsdoctor.commons.Strings.hasText;
import static com.depsdoctor.commons.config.ApiConfig.APIKEY_PREFIX;

/**
 * XygeniJwtDetector: Detects a hardcoded Xygeni JWT.
 * <p/>
 * The Xygeni token has a sub with the email of the user,
 * and 'apitokendata' with 'userBean' object with many fields, and a 'tokenId'
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class XygeniJwtDetector extends JwtDetector {

  /**
   * The Xygeni token has a "xya_" prefix, captured by the regular expression. The JWT token
   * follows. Here we remove the prefix so that the token could be validated by JwtDetector.isValidToken(String),
   * which in turn calls {@link #isValidToken(JWT)}.
   */
  @Override
  protected boolean isValidToken(String jwt) {
    // APIKEY_PREFIX is "xya_", prefix for Xygeni api tokens
    if(jwt == null || !jwt.startsWith(APIKEY_PREFIX)) return false;
    // remove prefix so JWT token could be validated
    return super.isValidToken(jwt.substring(APIKEY_PREFIX.length()));
  }

  /**
   * JwtDetector already parses the JWT token, here we do "semantic" validation
   * on the claims, to ensure that this is a valid Xygeni token.
   *
   * We could also run
   */
  @Override protected boolean isValidToken(JWT tok) {
    // alg is HS512
    if(!"HS512".equals(tok.getAlgorithm())) return false;
    // subject is the user email
    String sub = tok.getSubject();
    if(!hasText(sub) || !sub.contains("@")) return false;

    // apitokendata.tokenId must exist
    Object o = tok.getClaim("apitokendata");
    if(o instanceof JSONObject) {
      JSONObject atd = (JSONObject) o;
      o = atd.has("tokenId") ? atd.get("tokenId") : null;
      return o instanceof Number;
    }
    return false;
  }

}
