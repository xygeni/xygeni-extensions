package io.xygeni.report_load.trufflehog.model;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@JsonIgnoreProperties(ignoreUnknown = true)
@Getter @Setter
public class Data {
  // multiple json names to one object

  @JsonProperty
  @JsonAlias({
    "Azure",
    "Bitbucket",
    "Circleci",
    "Confluence",
    "Docker",
    "Ecr",
    "Gcs",
    "Github",
    "Gitlab",
    "Jira",
    "Npm",
    "Pypi",
    "S3",
    "Slack",
    "Filesystem",
    "Git",
    "Test",
    "Buildkite",
    "Gerrit",
    "Jenkins",
    "Teams",
    "Artifactory",
    "Syslog",
    "Forager",
    "Sharepoint",
    "GoogleDrive",
    "AzureRepos",
    "TravisCI",
    "Postman",
    "Webhook"
    })
  private SourceMetadataType sourceMetadataType;


  @Override
  public String toString() {
    return "Data{" +
      "sourceMetadataType=" + sourceMetadataType +
      '}';
  }
  

}
