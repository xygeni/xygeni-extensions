package io.xygeni.report_load.trufflehog;

import com.depsdoctor.core.model.secrets.PotentialSecret;
import com.depsdoctor.core.model.secrets.SecretsReport;
import com.depsdoctor.core.utils.secrets.SecretsReportLoader;
import io.xygeni.report_load.trufflehog.model.TrufflehogSecret;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link TrufflehogConverter}
 *
 * @author vdlr
 * @version 08-May-2024 (vdlr)
 */
public class TrufflehogConverterTest {

  @Test
  public void testTrufferhog() {

    // load test file from resources
    var truffehogJsonFile = getTestResourcesFile("webgoat_trufflehog_report.json-like");

    TrufflehogConverter converter = new TrufflehogConverter();
    TrufflehogSecret[] trufflehogSecrets = new TrufflehogLoader().load(truffehogJsonFile, "secrets-trufflehog");
    SecretsReport xygeniSecrets = converter.convert("secrets-trufflehog", truffehogJsonFile.getParentFile(), trufflehogSecrets);

    assertThat(xygeniSecrets).isNotNull();
    assertReport(xygeniSecrets, "secrets-trufflehog",truffehogJsonFile);

  }

  private static void assertReport(SecretsReport xygeni, String project, File file) {
    assertThat(xygeni.getMetadata().getProjectName()).isEqualTo(project);
    assertThat(xygeni.getMetadata().getDirectory()).isEqualTo(file.getParentFile());
    assertThat(xygeni.getSecrets()).hasSize(xygeni.getStatistics().getSecrets());
    assertThat(xygeni.getStatistics().getFiles()).isPositive();
    var secret = xygeni.getSecrets().getSecrets().iterator().next();
    assertThat(secret.getSecret()).isNotBlank();
  }

  private File getTestResourcesFile(String path) {
    var pfiles = TrufflehogConverterTest.class.getClassLoader().getResource(path);
    assertThat(pfiles).isNotNull();
    File f = new File(pfiles.getPath());
    assertThat(f.exists()).isTrue();
    return f;
  }
}
