package io.xygeni.extensions.custom_detectors.secrets;

import com.depsdoctor.commons.json.JsonSerializer;
import com.depsdoctor.commons.os.OS;
import io.xygeni.extensions.custom_detectors.TestHelper;
import org.junit.jupiter.api.Test;

import java.io.File;

import static java.lang.System.out;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

/**
 * DropboxDetectorTest - Unit tests for the custom Dropbox token leak detector.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class DropboxDetectorTest {

  @Test
  void detect() {
    File dir = TestHelper.getTestResourcesDir("secrets/dropbox");
    var ctx = SecretTestHelper.runOnFiles("custom_dropbox_token", dir, "custom_dropbox_token.yml");
    ctx.secrets().forEach(e -> out.println(JsonSerializer.dump(e, true)));
    var secrets = ctx.secrets().findByDetector("custom_dropbox_token");
    assertThat(secrets).hasSize(1);
    var secret = secrets.get(0);
    assertThat(secret.isInactive()).isTrue(); // that was a close one!
  }

  /** We do not want to leak real secrets! To test with a real thing, pass DROPBOX_TOKEN environment variable */
  @Test
  void detect_and_remediate_real_secret() {
    String leaked = OS.getProperty("DROPBOX_TOKEN");
    assumeThat(leaked).as("DROPBOX_TOKEN environment variable must be set for this test to work").isNotBlank();

    var ctx = SecretTestHelper.runOnText("custom_dropbox_token", leaked, "custom_dropbox_token.yml");

    var secrets = ctx.secrets().findByDetector("custom_dropbox_token");
    assertThat(secrets).hasSize(1);
    var secret = secrets.get(0);
    out.println(JsonSerializer.dump(secret, true));
  }


}
