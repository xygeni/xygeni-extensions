package io.xygeni.extensions.custom_detectors.sast.csharp;

import com.depsdoctor.core.model.sast.SastRule;
import io.xygeni.sankxy.csharp.expr.chain.CSharpCallSignature;
import io.xygeni.sankxy.csharp.predicates.CSharpPredicates;
import io.xygeni.sast.scanner.config.SastScanConfig;
import io.xygeni.sast.scanner.detector.csharp.CSharpRule;
import io.xygeni.sast.scanner.engine.SastContext;

import java.util.List;

import static com.depsdoctor.commons.Strings.dotJoin;
import static com.depsdoctor.commons.Strings.hasText;

/**
 * CustomDangerousApi - Detects use of potentially dangerous APIs
 * such as BinaryFormatter which can lead to deserialization vulnerabilities.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class CustomDangerousApi extends CSharpRule {

  private static final List<String> DEFAULT_BANNED = List.of(
      "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Serialize",
      "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize"
  );

  private List<String> banned;

  @Override
  public void configure(SastRule dc, SastScanConfig sc) {
    super.configure(dc, sc);

    banned = dc.getProperty("banned", DEFAULT_BANNED);
  }

  @Override
  protected void checkCall(CSharpCallSignature call, SastContext ctx) {
    if (!isBanned(call)) {
      return;
    }

    var toReport = CSharpPredicates.nodeToReport.apply(call.getNode());
    createIssue(ctx, toReport);
  }

  // IMPLEMENTATION
  protected String getSimpleCallSignature(CSharpCallSignature call) {
    var qualified = call.getName();
    var type = call.getAccessedType();
    if (type != null) {
      qualified = dotJoin(type.getType(), qualified);
    }

    return qualified;
  }

  private boolean isBanned(CSharpCallSignature call) {
    var qualified = getSimpleCallSignature(call);
    return hasText(qualified) && banned.contains(qualified);
  }
}
