package io.xygeni.extensions.custom_detectors.sast.java;

import com.depsdoctor.core.model.sast.SastRule;
import io.xygeni.sankxy.java.expr.chain.JavaCallSignature;
import io.xygeni.sankxy.java.model.CommonProperties;
import io.xygeni.sast.scanner.config.SastScanConfig;
import io.xygeni.sast.scanner.detector.java.JavaRule;
import io.xygeni.sast.scanner.engine.SastContext;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * CustomAvoidNativeCalls - Detects calls to native methods (JNI),
 * which can introduce security risks and platform dependencies.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class CustomAvoidNativeCalls extends JavaRule {

  private List<String> allowedMethods;

  @Override
  public void configure(SastRule dc, SastScanConfig sc) {
    super.configure(dc, sc);

    allowedMethods = dc.getProperty("allowedMethods", Collections.emptyList());
  }

  @Override
  protected void checkCall(JavaCallSignature call, SastContext ctx) {
    if (!isNativeCall(call)) return;

    createIssue(ctx, call.getNode());
  }

  // IMPLEMENTATION
  private boolean isNativeCall(JavaCallSignature call) {
    var functionInfo = call.getFunctionInfo();
    if (functionInfo == null || allowedMethods.contains(functionInfo.qualifiedName())) return false;

    var modifiersProp = functionInfo.getProperty(CommonProperties.modifiers);
    return modifiersProp instanceof Set && ((Set<?>) modifiersProp).contains("native");
  }
}
