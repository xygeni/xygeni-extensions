package io.xygeni.extensions.custom_detectors.sast.python;

import com.depsdoctor.core.model.sast.SastRule;
import com.google.common.collect.Sets;
import io.xygeni.sankxy.core.exception.AnalyzerTaskException;
import io.xygeni.sankxy.python.PythonNode;
import io.xygeni.sast.scanner.config.SastScanConfig;
import io.xygeni.sast.scanner.detector.model.web.python.frameworks.code.PythonFrameworkCodeConfigEntry;
import io.xygeni.sast.scanner.detector.model.web.python.frameworks.code.PythonFrameworkCodeConfigurationExtractor;
import io.xygeni.sast.scanner.detector.python.PythonRule;
import io.xygeni.sast.scanner.engine.SastContext;
import io.xygeni.sast.scanner.helper.UnsafeSessionConfigurationHelper;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.depsdoctor.commons.Strings.hasText;
import static io.xygeni.sast.scanner.helper.UnsafeSessionConfigurationHelper.*;
import static io.xygeni.sast.scanner.helper.python.DjangoMiddlewareHelper.findMiddlewareEntry;
import static io.xygeni.sast.scanner.helper.python.DjangoMiddlewareHelper.hasMiddleware;

/**
 * CustomDjangoUnsafeSessionConfiguration - Detects unsafe session configuration
 * in Django applications, including insecure cookie settings.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class CustomDjangoUnsafeSessionConfiguration extends PythonRule {

  private static final Set<String> PROPS_TO_CHECK = Set.of(
      "SESSION_COOKIE_HTTPONLY", "SESSION_COOKIE_SECURE", "SESSION_COOKIE_DOMAIN",
      "SESSION_COOKIE_PATH", "SESSION_COOKIE_AGE", "SESSION_COOKIE_SAMESITE"
  );

  protected UnsafeSessionConfigurationHelper<PythonNode> helper;

  @Override
  public void configure(SastRule dc, SastScanConfig sc) {
    super.configure(dc, sc);

    var checkPersistence = dc.getProperty("checkPersistence", DEFAULT_CHECK_PERSISTENCE);
    var invalidDomainPattern = Pattern.compile(dc.getProperty("invalidDomainPattern", DEFAULT_INVALID_DOMAIN_PATTERN));
    var invalidPathPattern = Pattern.compile(dc.getProperty("invalidPathPattern", DEFAULT_INVALID_PATH_PATTERN));
    var enforceHttpOnly = dc.getProperty("enforceHttpOnly", DEFAULT_ENFORCE_HTTP_ONLY);
    var enforceSecure = dc.getProperty("enforceSecure", DEFAULT_ENFORCE_SECURE);
    var sameSiteValue = dc.getProperty("sameSiteValue", DEFAULT_SAME_SITE_VALUE);

    helper = new UnsafeSessionConfigurationHelper<>(
        this, false, false, false, checkPersistence,
        invalidDomainPattern, invalidPathPattern, enforceHttpOnly, enforceSecure, sameSiteValue
    );
  }

  @Override
  public void scan(PythonNode root, SastContext ctx) throws AnalyzerTaskException {
    var configEntries = PythonFrameworkCodeConfigurationExtractor.extractDjangoConfig(root, ctx);
    if (configEntries.isEmpty() || !usesSessionMiddleware(configEntries)) return;

    var checkedProps = Sets.newHashSet();
    for (var entry : configEntries) {
      checkCookieProp(entry.getKey(), entry, ctx);
      checkedProps.add(entry.getKey());
    }

    var missingProps = PROPS_TO_CHECK.stream()
        .filter(prop -> !checkedProps.contains(prop))
        .collect(Collectors.toSet());
    for (var prop : missingProps) {
      checkDefaultCookieProp(prop, root, ctx);
    }
  }

  // IMPLEMENTATION
  private void checkCookieProp(String propToMatch, PythonFrameworkCodeConfigEntry entry, SastContext ctx) {
    if (!hasText(propToMatch)) return;

    var location = buildLocation(entry.getWhere(), ctx);

    switch (propToMatch) {
      case "SESSION_COOKIE_HTTPONLY":
        var isHttpOnly = entry.valueAsBoolean(getEvaluator());
        helper.check("cookie_httponly", isHttpOnly, location, ctx);
        break;

      case "SESSION_COOKIE_SECURE":
        var isSecure = entry.valueAsBoolean(getEvaluator());
        helper.check("cookie_secure", isSecure, location, ctx);
        break;

      case "SESSION_COOKIE_DOMAIN":
        var domain = entry.valueAsString(getEvaluator());
        helper.check("cookie_domain", domain, location, ctx);
        break;

      case "SESSION_COOKIE_PATH":
        var path = entry.valueAsString(getEvaluator());
        helper.check("cookie_path", path, location, ctx);
        break;

      case "SESSION_COOKIE_AGE":
        var maxAge = entry.valueAsLong(getEvaluator());
        helper.check("cookie_lifetime", maxAge, location, ctx);
        break;

      case "SESSION_COOKIE_SAMESITE":
        var sameSite = entry.valueAsString(getEvaluator());
        helper.check("cookie_samesite", sameSite, location, ctx);
    }
  }

  private void checkDefaultCookieProp(String propToMatch, PythonNode where, SastContext ctx) {
    if (!hasText(propToMatch)) return;

    var location = buildLocation(where, ctx);

    switch (propToMatch) {
      case "SESSION_COOKIE_HTTPONLY":
        helper.check("cookie_httponly", false, location, ctx);
        break;

      case "SESSION_COOKIE_SECURE":
        helper.check("cookie_secure", false, location, ctx);
        break;

      case "SESSION_COOKIE_PATH":
        helper.check("cookie_path", "/", location, ctx);
        break;

      case "SESSION_COOKIE_AGE":
        helper.check("cookie_lifetime", 1209600, location, ctx);
        break;

      case "SESSION_COOKIE_SAMESITE":
        helper.check("cookie_samesite", "Lax", location, ctx);
    }
  }

  private boolean usesSessionMiddleware(List<PythonFrameworkCodeConfigEntry> configEntries) {
    var middlewareEntry = findMiddlewareEntry(configEntries);
    return hasMiddleware(middlewareEntry, "django.contrib.sessions.middleware.SessionMiddleware"::equals);
  }
}
