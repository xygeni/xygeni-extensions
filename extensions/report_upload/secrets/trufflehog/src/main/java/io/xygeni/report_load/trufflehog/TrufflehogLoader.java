package io.xygeni.report_load.trufflehog;


import com.depsdoctor.commons.io.IO;
import com.depsdoctor.commons.json.JsonDeserializer;
import io.xygeni.report.load.JsonLoader;
import io.xygeni.report.load.ReportLoadException;
import io.xygeni.report_load.trufflehog.model.TrufflehogSecret;
import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Trufflehog secret loader.
 * <p>
 * A json like export from trufflehog can be obtained by using "--json" option and redirecting output to file.
 * The exported file will contain several lines in json format that can be load using this loader.
 *
 * @author vdlr
 * @version 08-May-2024 (vdlr)
 */
public class TrufflehogLoader extends JsonLoader<TrufflehogSecret[]> {

  private final Logger log = LoggerFactory.getLogger(TrufflehogLoader.class);

  public TrufflehogLoader() { super(TrufflehogSecret[].class); }

  @Override
  public TrufflehogSecret[] load(@NonNull File file, String format) throws ReportLoadException {
    try(BufferedReader reader = IO.openReader(file, UTF_8)) {
      return getTrufflehogSecrets(reader, format);

    } catch (IOException e) {
      throw ReportLoadException.errorLoadingReport(file.getName(), format, e);
    }
  }

  @Override
  public TrufflehogSecret[] load(@NonNull Reader reader, String format) throws ReportLoadException {
    try(BufferedReader breader = IO.openReader(reader)) {
      return getTrufflehogSecrets(breader, format);

    } catch (IOException e) {
      throw ReportLoadException.errorLoadingReport("-", format, e);
    }
  }


  @Override
  public boolean isValid(Reader reader, String filename, String format) throws ReportLoadException {
    if(!"secrets-trufflehog".equals(format)) return false; // only supports this format

    try(BufferedReader breader = IO.openReader(reader)) {
      String line;
      while ((line = breader.readLine()) != null) {
        if (line.contains("\"SourceMetadata\":")) return true; // it's looks like a trufflehog report
      }
    } catch (IOException e) {
      throw ReportLoadException.errorLoadingReport(filename, format, e);
    }

    return false;
  }



  private TrufflehogSecret[] getTrufflehogSecrets(BufferedReader breader, String format) throws IOException {

    // Trufflehog export generate an array of json elements, each element could be a TrufflehogSecret or a log line
    // log-line format:
    //    {"level":"info-0","ts":"2024-05-08T01:15:26+02:00","logger":"trufflehog","msg":"running source","source_manager_worker_id":"3DFjJ","with_units":true}
    // secret json format:
    //    {"SourceMetadata":{"Data":{"Filesystem":{"file":"./my-repo/secret.yaml","line":7}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":15,"DetectorName":"PrivateKey","DecoderName":"BASE64","Verified":true,"Raw":"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r...-----END OPENSSH PRIVATE KEY-----\n","RawV2":"","Redacted":"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5v","ExtraData":{"github_user":"agituser"},"StructuredData":null}

    List<TrufflehogSecret> secretListTmp = new ArrayList<>();
    var dr = JsonDeserializer.deserializationReader(TrufflehogSecret.class);
    String line;
    while ((line = breader.readLine()) != null) {
      if (line.contains("\"SourceMetadata\":")) {
        log.debug("secret detected: {}", line);
        TrufflehogSecret secret = dr.readValue(line);
        if(secret != null) secretListTmp.add(secret);
      } else {
        log.debug("line discarded: {}", line);
      }
    }
    return secretListTmp.toArray(new TrufflehogSecret[0]);
  }

}

