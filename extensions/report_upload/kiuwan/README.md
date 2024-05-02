# Report upload for Kiuwan

## About

Kiuwan is a powerful, end-to-end application security platform. Kiuwan Static Application Security Testing (SAST) product is the tool that detects security vulnerabilities in source code using static analysis.

The problem is that Xygeni does not provide a mechanism in the agent (Kiuwan Local Analyzer) for writing to a local file the findings from the tool.

## How report extraction works

The Kiuwan scanner (Kiuwan Local Analyzer) by default uploads its findings to the Kiuwan platform. 

To export the findings to a local file for uploading into third-party tools like Xygeni, the approach used was to register the custom rule [ExportRule](src/main/java/ext/kiuwan/ExportRule.java) provided that registers a task to export the findings at the end of the analysis, using the standard-provided report formatter for the `xml_issues` report, the same format that the agent uses to send the findings to the Kiuwan on-cloud service.

## Steps

### 1. Compile the extraction rule (optional)

The rule JAR and rule descriptors are already provided in the [dist](dist) directory for your convenience. Anyway, the jar with the compile rule could be generated using Maven:

```console
$ mvn package
```

The compilation will copy the jar into `dist` and run the [generate_rules.sh](bin/generate_rules.sh) script to create a rule descriptor for each technology, which stores all rule desccriptors into [dist/rules](dist/rules).

> [!NOTE]
> As Kiuwan only allows one technology in a rule descriptor, it is necessary to generate a descriptor for each technology available. The `OPT.CRITERIUM_VALUE.LANGUAGE_PARSER.<TECH>` is set on each rule descriptor.

### 2. Install rules and jar file

Next, follow the instructions to upload the [kiuwan-export-rule jar](dist/kiuwan-export-rule-1.0.jar) and the [rule descriptors](dist/rules) to Kiuwan.

Read [Installing custom rules created with Kiuwan Rule Developer](https://www.kiuwan.com/docs/display/K5/Installing+custom+rules+created+with+Kiuwan+Rule+Developer) in Kiuwan documentation for full details on how to install rule definitions and their implementations, so the exporter rule may work at your installation. You need also to add the imported rules to an existing model, so the local analyzer will download them.

Once rules and jar uploaded and added to the Kiuwan model, the local analyzer will execute the exporter rule when the output report is given, so it can be uploaded into Xygeni. 

### 3. Run the scan

Run the Kiuwan Local Analyzer with the path to the report file provided in the `KIUWAN_JSON_REPORT` environment variable. 

```console
$ KIUWAN_JSON_REPORT=/path/to/my/report.xml
$ agent.sh -s DIR -n NAME -c
...
Report file available at: /path/to/my/report.xml
```

> [!NOTE]
> The export rule does nothing if the `KIUWAN_JSON_REPORT` is not given. The path for the report could be absolute or relative. When relative, the path is prefixed with `$HOME` (the OS user home directory) 

### 4. Upload the Kiuwan report to Xygeni

Use the `xygeni report-upload` command for uploading the exported report, after normalization to the Xygeni SAST format.

```
xygeni report-upload --report=/path/to/my/report.xml --format sast-kiuwan
```