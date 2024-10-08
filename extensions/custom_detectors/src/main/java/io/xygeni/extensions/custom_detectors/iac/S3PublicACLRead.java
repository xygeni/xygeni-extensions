package io.xygeni.extensions.custom_detectors.iac;

import com.depsdoctor.iac.scanner.config.DetectorConfig;
import com.depsdoctor.iac.scanner.config.IacScanConfig;
import com.depsdoctor.iac.scanner.detector.terraform.TerraformDetector;
import com.depsdoctor.iac.scanner.engine.IacContext;
import com.depsdoctor.stan.scanner.parser.iac.model.terraform.AttributeValue;
import com.depsdoctor.stan.scanner.parser.iac.model.terraform.Configuration;
import com.depsdoctor.stan.scanner.parser.iac.model.terraform.Resource;

import java.util.Set;

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
