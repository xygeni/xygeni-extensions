# IaC Flaws Detector

The Internet-as-Code (IaC) Flaws detection analyzes issues in IaC templates, by running the [IaC Scanner](https://docs.xygeni.io/xygeni-products/iac-security/iac-scanner) over your templates.

IaC templates are encoded using different frameworks. Examples are Ansible Playbooks, Azure Bicep, Azure Resource Manager (ARM), Chef Infra cookbooks, AWS CloudFormation, Terraform Configurations, Kubernetes YAML Manifests, Helm Charts, Dockerfiles, Pulumi YAML, etc.

The cloud templates typically declare the configuration of assets, and may have a variety of IaC flaws that can be detected.
Xygeni provides many out-of-the-box IaC flaw detectors, but you can also create your own.

Creating a detector for an IaC Flaw includes a [YAML configuration file](https://docs.xygeni.io/xygeni-products/iac-security/iac-scanner/iac-scanner-configuration) and an AsciiDoc documentation file. The goal of the detector is to identify some violation of a good practice or security issue in assets or configurations in IaC templates.

There are two options for developing an IaC Flaw detector:

## XYPOL (Xygeni Policy Language)

The first option is to use [XYPOL](XYPOL.adoc). XYPOL is a high-level language that analyzes IaC assets (resources, data sources...). XYPOL encodes a _policy rule_ that specifies which configurations are properly implemented.

XYPOL code can be written directly in the detector YAML file, in the `xypol` attribute. 

A simple detector for Google Cloud service accounts written in XYPOL is shown below:

```php
# GCP service accounts must NOT have public_key_data:

ON account FROM 'google_service_account_key'
WHERE NOT EXISTS account.public_key_data;
```

## Java implementation

The detection logic could be implemented in a Java class. The interface `IacFlawDetector` declares the methods to be implemented (`accept`, `detect`) and optional lifecycle methods that could be overwritten:

```java
public interface IacFlawDetector {
  /** Called when instantiated */
  void configure(DetectorConfig dc, IacScanConfig sc);

  /** Called on engine start, before processing files */
  void initialize(IacContext ctx) throws DetectorInitException;

  /** * If true, this detector is valid for the given file (path and inferred type). */
  boolean accept(@NonNull String filePath, FileType type);

  /** Called on each Entry extracted by the matching parser */
  void detect(IacTemplate e, IacContext ctx) throws DetectorException;

  /** Called on engine end, after files processed */
  void terminate(IacContext ctx) throws DetectorInitException;
}
```

Detector implementation often extends the base class `com.depsdoctor.iac.scanner.detector.BaseIacFlawDetector` but more typically extends the base class for the framework, for example:
- `AnsibleDetector` (for RedHat Ansible),
- `ArmDetector` (for Azure Resource Manager),
- `CfDetector` (for AWS CloudFormation),
- `DockerDetector` (for Dockerfiles or docker composer),
- `HelmDetector` (for Helm Charts),
- `KubernetesDetector` (for Kubernetes YAML Manifests),
- `TerraformDetector` (for Terraform Configurations).

Such base classes provide default implementations and helper methods for creating and reporting an `IacFlaw`.

## Examples

### Public-facing ALB not protected by WAF

Imagine that your security policy requires that every public-facing application load balancer (ALB) be protected by a web application firewall (WAF). For AWS and Terraform, that requirement could be expressed using XYPOL. Any resource (load balancer) not matching the policy will be reported:

```php
# The terraform services for load balancer or alb
ON lb FROM resource_type IN ['aws_lb', 'aws_alb']
WHERE
  # The load balancer is either protected by WAF...
  lb CONNECTED_TO acl FROM resource_type IN ['aws_wafv2_web_acl_association', 'aws_wafregional_web_acl_association'] OR 
  # not public-facing...
  lb.internal = true OR 
  # or not an application load balancer
  lb.load_balancer_type IN ['network', 'gateway'];  
```

See [alb_protected_by_waf](../src/main/resources/iac/custom_alb_protected_by_waf.yml) detector for the full definition. Please follow the [XYPOL guide](XYPOL.adoc) for more details on how to declare your own policies.

### S3 Bucket ACL allows public read access

As an example of a detector implemented using the Xygeni framework, the [s3_bucket_acl_read_to_all](../src/main/resources/iac/custom_s3_bucket_acl_read_to_all.yml) detector is provided. This detector checks if the bucket ACL allows public read access to all users, using the following `S3PublicACLRead` implementation class:

```java
/**
 * S3PublicACLRead - S3 Bucket has an ACL defined which allows public READ/WRITE access.
 * <p>
 * Please note that the acl attribute in aws_s3_bucket is deprecated,
 * replaced by aws_s3_bucket_acl resource.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class S3PublicACLRead extends TerraformDetector {
  private static final Set<String> FORBIDDEN = Set.of(
    "public-read", "public-read-write", "website", "authenticated-read"
  );

  private Set<String> forbidden = FORBIDDEN;

  @Override public void configure(DetectorConfig dc, IacScanConfig sc) {
    super.configure(dc, sc);
    // this is how
    forbidden = dc.getProperty("forbidden", FORBIDDEN);
  }

  @Override protected void detect(Configuration conf, IacContext ctx) {
    // This is an example of how to process a terraform configuration, looking for assets of type 'aws_s3_bucket'
    for(var bucket : resources(conf, "aws_s3_bucket")) {
       // acl attribute in aws_s3_bucket is deprecated
       var acl = bucket.getAttribute("acl");
       if (isTooPermissive(acl)) {
         // flaw on the bucket's acl attribute and bucket resource
         createFlaw(ctx, bucket.qualifiedResource(), location(acl, ctx));

       } else {
         // look for linked aws_s3_bucket_acl
         for(var bucketAcl : incoming(bucket, "bucket", conf, Resource.class, pred("aws_s3_bucket_acl"))) {
           acl = bucketAcl.getAttribute("acl");
           if(isTooPermissive(acl)) {
             // emit flaw on the acl attribute of bucket_acl, but resource = bucket
             var flaw = createFlaw(ctx, bucket.qualifiedResource(), location(acl, ctx));
             flaw.addProperty("bucket_acl", bucketAcl.getId());
           }
         }
       }
     }
  }

  /** No ACL attribute is too permissive; also any forbidden attribute is also considered too permissive */
  private boolean isTooPermissive(AttributeValue acl) {
    if(acl==null) return false;
    String v = acl.asString("");
    return v != null && forbidden.contains(v);
  }
}
```

The essential parts of the detector are:

```java
@Override protected void detect(Configuration conf, IacContext ctx) {
  // This is an example of how to process a terraform configuration, looking for assets of type 'aws_s3_bucket'
  for (var bucket : resources(conf, "aws_s3_bucket")) {
    // ...
    // look for linked aws_s3_bucket_acl via the 'bucket' field
    for (var bucketAcl : incoming(bucket, "bucket", conf, Resource.class, pred("aws_s3_bucket_acl"))) {
      // ...
      // emit flaw on the acl attribute of bucket_acl, but resource = bucket
      createFlaw(ctx, bucket.qualifiedResource(), location(acl, ctx));
    }
  }
}
```

The methods `createFlaw`, `location`, `resources`, `incoming` and `pred` are provided by the base class for emitting the flaw, resolving the location of the offending asset, traversing assets of the requested types, and looking for linked assets.
