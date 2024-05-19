package io.xygeni.report_load.trufflehog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@JsonIgnoreProperties(ignoreUnknown = true)
@Getter @Setter 
public class SourceMetadataType {

  // generic implementation of source metadata types
  // see https://github.com/trufflesecurity/trufflehog/blob/main/pkg/pb/source_metadatapb/source_metadata.pb.go

  @JsonProperty("file") private String file;
  @JsonProperty("email") private String email;
  @JsonProperty("line") private int line;
  @JsonProperty("repository") private String repository;
  @JsonProperty("commit") private String commit;
  @JsonProperty("timestamp") private String timestamp;

  @Override
  public String toString() {
    return "Filesystem{" +
      "file='" + file + '\'' +
      ", line=" + line +
      ", email=" + email +
      ", repository=" + repository +
      ", commit=" + commit +
      ", timestamp=" + timestamp +
      '}';
  }
}
