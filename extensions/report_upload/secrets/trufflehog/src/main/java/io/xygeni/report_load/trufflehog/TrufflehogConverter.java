package io.xygeni.report_load.trufflehog;

import com.depsdoctor.core.model.common.Confidence;
import com.depsdoctor.core.model.common.ReportProperties;
import com.depsdoctor.core.model.common.Severity;
import com.depsdoctor.core.model.files.FileType;
import com.depsdoctor.core.model.secrets.PotentialSecret;
import com.depsdoctor.core.model.secrets.SecretType;
import com.depsdoctor.core.model.secrets.SecretsReport;
import com.depsdoctor.commons.security.Obfuscator;
import io.xygeni.report.load.BaseReportConverter;
import io.xygeni.report.load.ReportConverterException;
import io.xygeni.report_load.trufflehog.model.TrufflehogSecret;
import org.apache.commons.lang3.EnumUtils;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.time.Instant;

import static com.depsdoctor.commons.Strings.hasText;
import static com.depsdoctor.core.model.files.FileType.fileType;
import static org.apache.commons.io.FilenameUtils.getExtension;
import static com.depsdoctor.commons.time.TimestampHelper.isValidInstant;

/**
 * This converter will convert the Trufflehog report into a SecretsReport by mapping each Trufflehog detector to xygeni SecretType.
 *
 *
 * @author vdlr
 * @version 9-May-2024 (vdlr)
 */
public class TrufflehogConverter extends BaseReportConverter<TrufflehogSecret[], SecretsReport> {

  public static final String TOOL = "Trufflehog";

  private static final Map<String, String> trufflehogdetector2secretType;

  static {
    Map<String, String> m = Map.of();
    try {
      Properties p = new Properties();
      var in = TrufflehogConverter.class.getResourceAsStream("/Trufflehog.properties");
      if(in != null) {
        p.load(in);
        //noinspection unchecked,rawtypes
        m = (Map) p;

      } else {
        LoggerFactory.getLogger(TrufflehogConverter.class).warn("Trufflehog.properties not found");
      }

    } catch (IOException e) {
      m = Map.of();
    }
    trufflehogdetector2secretType = m;
  }



  @Override
  public SecretsReport convert(String projectName, File directory, TrufflehogSecret[] source) throws ReportConverterException {

    // here we need to convert the source into a SecretsReport
    SecretsReport report = new SecretsReport(projectName, directory, null, false, null);

    // set the tool name in the report metadata
    report.getMetadata().addReportProperty(ReportProperties.toolName, TOOL);

    Set<String> seen = new TreeSet<>();

    // loop over the secrets found by Trufflehog tool and add them to the xygeni secrets report
    for(TrufflehogSecret trufflehogSecret : source) {

      // convert the trufflehog secret into a xygeni PotentialSecret
      PotentialSecret secret = parseSecret(trufflehogSecret, directory);

      // add the secret to the report
      report.addSecret(secret);

      // add the file to the statistics if it is new
      var path = secret.getFile();
      if(hasText(path) && seen.add(path)) {
        // new file
        FileType fileType = fileType(getExtension(path));
        report.getStatistics().addFile(fileType.name());
      }
    }

    return report;
  }

  private PotentialSecret parseSecret(TrufflehogSecret trufflehogSecret, File directory) {

    // a PotentialSecret require a secret, a detector, and a location
    // Trufflehog secret data structure is documented here:
    // https://github.com/trufflesecurity/trufflehog/blob/ead9dd57486f43830ba2279f3a3c49d4b9c36633/pkg/output/json.go#L27

    String check = trufflehogSecret.getDetectorName() == null ? "trufflehog" : trufflehogSecret.getDetectorName();
    SecretType type = getSecretType(trufflehogSecret);
    String ofuscated = trufflehogSecret.getRedacted();
    if(!hasText(ofuscated)) ofuscated = Obfuscator.truncateMiddle(trufflehogSecret.getRaw());

    String key = trufflehogSecret.getRaw() != null && trufflehogSecret.getRawV2() != null && trufflehogSecret.getRawV2().length() > trufflehogSecret.getRaw().length() ?
      trufflehogSecret.getRawV2().substring(trufflehogSecret.getRaw().length()) : "-"; // rawV2 is raw + keyID

    var sourceData = trufflehogSecret.getSourceMetadata().getData().getSourceMetadataType();
    String file = sourceData.getFile() != null ? sourceData.getFile() : "-";
    int line = sourceData.getLine();

    var secretBuilder = PotentialSecret
    .clearText(ofuscated, type, check, key, "-")
    .location(file, line, line)
    .severity(trufflehogSecret.isVerified() ? Severity.critical : Severity.low)
    .confidence(trufflehogSecret.isVerified() ? Confidence.highest : Confidence.medium);

    String email = sourceData.getEmail();
    String user = hasText(email) ? email : "-";
    String ts = sourceData.getTimestamp() != null ? sourceData.getTimestamp() : null;
    long timestamp = isValidInstant(ts) ? Instant.parse(ts).toEpochMilli() : System.currentTimeMillis();

    String commitSha = sourceData.getCommit() != null ? sourceData.getCommit() : null;

    if(commitSha != null) secretBuilder.scm(commitSha, timestamp, user, user);

    var ps = secretBuilder.build();

    boolean isGeneric =
      type == SecretType.base64 || type == SecretType.comment ||
        type == SecretType.high_entropy || type == SecretType.keyword || type == SecretType.password;
    ps.setGeneric(isGeneric);
    ps.setNew(true);

    return ps;
  }

  private SecretType getSecretType(TrufflehogSecret trufflehogSecret) {
    int detector = trufflehogSecret.getDetectorType();
    String s = trufflehogdetector2secretType.getOrDefault(String.valueOf(detector), SecretType.other.name());
    return EnumUtils.getEnum(SecretType.class, s, SecretType.other);
  }


}


