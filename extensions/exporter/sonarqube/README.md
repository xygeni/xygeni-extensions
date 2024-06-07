# Report exporter for Sonar

## About

SonarQube provides SAST (Static Application Security Testing) tools in both server and SaaS versions. 

Xygeni provides a report uploader for SonarQube but does not provide a mechanism to download vulnerabilities data from Sonar platform.

Following can find out how to export findings from SonarQube using Web API to a json file that can be loaded to Xygeni.


## Python exporter

Use the `generate_report.py` python script to export findings from SonarQube to a json file.
It allows setting the SonarQube server URL and the SonarQube API token in case of private SonarQube installation. And it also allows setting the SonarCloud url and the SonarCloud API token in case of SonarCloud SaaS service.


```console

# Replace variables in generate_report.py with your SonarQube details:

# sonarqube_url = "https://your-sonarqube-server" or "https://sonarcloud.io"
# api_key = "your-api-key" # For SonarQube
# bearer_token = "your-bearer-token" # For SonarCloud
# project_key = "your-project-key"

# run the script
$ python generate_report.py
...
SonarQube data saved to sonarqube.report.json

```


## Upload the Sonar report to Xygeni

Use the `xygeni report-upload` command for uploading the exported report, after normalization to the Xygeni SAST format.

```
xygeni report-upload --report=/path/to/my/sonarqube.report.json --format sast-sonarqube

or 

xygeni report-upload --report=/path/to/my/sonarcloud.report.json --format sast-sonarcloud

```

