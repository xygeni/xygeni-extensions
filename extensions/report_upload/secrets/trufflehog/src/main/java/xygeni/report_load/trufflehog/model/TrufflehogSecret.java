package xygeni.report_load.trufflehog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;


/**
 * @author vdlr
 * @version 10-May-2024 (vdlr)
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@Getter @Setter
public class TrufflehogSecret {

  @JsonProperty("SourceMetadata") private SourceMetadata sourceMetadata;

  @JsonProperty("SourceID") private int sourceID;

  @JsonProperty("SourceType") private int sourceType;

  @JsonProperty("SourceName") private String sourceName;

  @JsonProperty("DetectorType") private int detectorType;

  @JsonProperty("DetectorName") private String detectorName;

  @JsonProperty("DecoderName") private String decoderName;

  @JsonProperty("Verified") private boolean verified;

  @JsonProperty("Raw") private String raw;

  @JsonProperty("RawV2") private String rawV2;

  @JsonProperty("Redacted") private String redacted;

  @JsonProperty("ExtraData") private Object extraData;

  @JsonProperty("StructuredData") private Object structuredData;

  @Override
  public String toString() {
    return "TrufflehogReport{" +
      "sourceMetadata=" + sourceMetadata +
      ", sourceID=" + sourceID +
      ", sourceType=" + sourceType +
      ", sourceName='" + sourceName + '\'' +
      ", detectorType=" + detectorType +
      ", detectorName='" + detectorName + '\'' +
      ", decoderName='" + decoderName + '\'' +
      ", verified=" + verified +
      ", raw='" + raw + '\'' +
      ", rawV2='" + rawV2 + '\'' +
      ", redacted='" + redacted + '\'' +
      ", extraData=" + extraData +
      ", structuredData=" + structuredData +
      '}';
  }

}

