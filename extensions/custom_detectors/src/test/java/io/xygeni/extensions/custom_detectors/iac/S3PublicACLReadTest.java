package io.xygeni.extensions.custom_detectors.iac;

import com.depsdoctor.iac.scanner.engine.IacContext;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static io.xygeni.extensions.custom_detectors.iac.IacRuleTestHelper.assertResult;
import static io.xygeni.extensions.custom_detectors.iac.IacRuleTestHelper.runTerraform;

class S3PublicACLReadTest {
  private static final String ID = "custom_s3_bucket_acl_read_to_all";
  private static final String PATH = ID;

  @Test public void test() {
    IacContext ctx = runTerraform(ID, new S3PublicACLRead(), PATH, dc -> {
      dc.addProperty("forbidden", Set.of("public-read", "public-read-write", "website", "authenticated-read"));
    });
    //System.out.println(ctx.flaws());
    assertResult(ctx, PATH);
  }

  @Test public void test_website_allowed() {
    // Simulates that the user allowed website canned ACL
    IacContext ctx = runTerraform(ID, new S3PublicACLRead(), PATH, dc -> {
      dc.addProperty("forbidden", Set.of("public-read", "public-read-write", "authenticated-read"));
    });
    //System.out.println(ctx.flaws());
    assertResult(ctx, Set.of("main.tf:aws_s3_bucket:bad_0"));
  }

  @Test public void test_website_ignored() {
    // Simulates that the user allowed website canned ACL
    IacContext ctx = runTerraform(ID, new S3PublicACLRead(), PATH, dc -> {
      dc.addProperty("forbidden", Set.of("public-read", "public-read-write", "website", "authenticated-read"));
      dc.setResourcesToIgnore(new String[] {":website$"} );
    });
    //System.out.println(ctx.flaws());
    assertResult(ctx, Set.of("main.tf:aws_s3_bucket:bad_0"));
  }

}