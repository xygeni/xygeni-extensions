package xygeni.report_load.trufflehog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@JsonIgnoreProperties(ignoreUnknown = true)
@Getter @Setter
public class SourceMetadata {

  @JsonProperty("Data") private Data data;

  @Override
  public String toString() {
    return "SourceMetadata{" +
      "data=" + data +
      '}';
  }
}
