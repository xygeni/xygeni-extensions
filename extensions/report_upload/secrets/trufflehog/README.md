# Report upload for Trufflehog

## About

[Trufflehog](https://github.com/trufflesecurity/trufflehog) is an open-source security tool that hunts for sensitive information like passwords and API keys. It scans code repositories, file systems, and even cloud storage for these secrets, helping developers and security teams ensure they aren't accidentally exposed.  With Trufflehog, you can unearth hidden secrets and keep your code safe.

Through this document, we will show how to create a custom report converter for Trufflehog from scratch and upload Trufflehog findings to Xygeni.

## Steps to generate a Custom Report Converter 

### Add new Trufflehog report upload definition

By adding a new Trufflehog report definition to `xygeni.custom.report-upload.yml` you will be able to use it in the `report-upload` command.

    secrets-trufflehog:
      enabled:     true
      description: Secrets detected by TruffleHog, in JSON format
      types:       application/json
      loader:      my_org.xygeni.report-load.trufflehog.TruffleHogLoader
      converter:   my_org.xygeni.report-load.trufflehog.TruffleHogConverter

The new secrets-trufflehog will be listed as a new available format,
so you may upload findings from trufflehog with:

    $>xygeni report-upload -r TRUFFLE_SECRETS.json -f secrets-trufflehog

Three classes should be implemented to load and convert the Trufflehog report:

* `my_org.xygeni.report_load.trufflehog.TruffleHogLoader` 
* `my_org.report.report_load.trufflehog.TruffleHogConverter`
* `my_org.report.report_load.trufflehog.TruffleHogSecret`, that class represent a Trufflehog secret in json format parsed by TrufflehogLoader and converted to xygeni report format by TrufflehogConverter.

### Implementing the converter

The converter should be implemented in the `my_org.report.report_load.trufflehog.TruffleHogConverter` class.

Here is a sample implementation, take a look of the final implementation at [TrufflehogConverter](src/main/java/my_org/xygeni/report_load/trufflehog/TruffleHogConverter.java) 

    public class TrufflehogConverter extends BaseReportConverter<TrufflehogReport, SecretsReport> {
     
      @Override
      public SecretsReport convert(String projectName, File directory, TrufflehogReport source) throws ReportConverterException {

        // here we need to convert the source into a SecretsReport
        SecretsReport report = new SecretsReport(projectName, directory, TOOL);

        // loop over the secrets found by Trufflehog and add them to the xygeni secrets report
        for(Secret trufflehogSecret : source.getSecrets()) {

          // convert the trufflehog secret into a xygeni PotentialSecret
          PotentialSecret xygeniSecret = parseSecret(trufflehogSecret, directory);

          // add the secret
          report.addSecret(xygeniSecret);
        }

        return report;
      }
    }

### Implementing the loader

The loader should be implemented in the `my_org.xygeni.report_load.trufflehog.TruffleHogLoader` class.

Here is a sample implementation, take a look of the final implementation at [TrufflehogLoader](src/main/java/my_org/xygeni/report_load/trufflehog/TruffleHogLoader.java)

    // use a JsonLoader if the report is in json format 
    public class TrufflehogLoader extends JsonLoader<TrufflehogSecret[]> {
 
      // Trufflehog secrets will be handle as an array      
      public TrufflehogLoader() { super(TrufflehogSecret[].class);}

      // check if the report is a trufflehog report by looking for the "SourceMetadata" field
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

      // A json like export from trufflehog can be obtained by using "--json" option and redirecting output to file. 

      // The exported file will contain several lines in json format, 
      // but the export is not a json complaining so it require to implement the load method in this case. It can be 

    }

### Mapping Trufflehog detectors to xygeni secret types

Secrets types found by Trufflehog detectors should be mapped to Xygeni Secret types. [Trufflehog.properties](src/main/resources/Trufflehog.properties) file contains the list of Trufflehog detectors and their corresponding Xygeni Secret types.

### Setup the environment

    Converter folder structure:

    /bin - contains the converter compile and package script
    /lib - contains the converter code
    /src/main/java - contains the converter source code
    /src/main/resources - contains the converter resources
    /classes - generated folder where compiled classes will be copied to

To compile and package the converter its required some libraries that can be copied from the Xygeni scanner lib folder. 
The file `lib/copy-here.txt` contains the list of required libraries, and  `compile-and-package-converter.sh` script can be used to compile and package the converter. 

Finally copy the `trufflehog-converter.jar` generated to the xygeni scanner `/conf` folder and execute the following command to upload a result of Trufflehog secrets analysis to Xygeni. 

    # upload webgoat repository report of Trufflehog analysis example to xygeni
    ./xygeni -v report-upload -r test/webgoat_trufflehog_report.json-like -f secrets-trufflehog