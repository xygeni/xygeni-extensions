package ext.kiuwan;

import com.als.core.AbstractRule;
import com.als.core.RuleContext;
import com.als.core.io.IOUtils;
import com.als.core.renderers.RenderException;
import com.als.core.renderers.Renderer;
import com.als.core.renderers.XmlIssuesRenderer;
import com.als.core.util.StringUtil;
import com.als.core.util.SysUtils;
import com.optimyth.qaking.task.OneShotTask;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;

/**
 * ExportRule is a pseudo-rule that exports the Kiuwan SAST report to XML ('xml_issues' format),
 * for importing the raw scanner findings into other tools, like ASOC / ASPM.
 * <p>
 * The rule does not create any issue. It simply registers a {@link ReportExportTask} as a POST_PROCESS task
 * to be run at the end of the analysis. This task exports the report to XML, using the 'KIUWAN_JSON_REPORT'
 * property (either environment variable or java system property).
 *
 * @author lrodriguez
 * @version 30-Apr-2024 (lrodriguez)
 */
public class ExportRule extends AbstractRule {
  @Override public boolean accept(String technology, RuleContext ctx) {
    return true; // valid for any tech
  }

  @Override public void initialize(RuleContext ctx) {
    super.initialize(ctx);

    ReportExportTask exporter = new ReportExportTask();
    ctx.getAnalysisTasks().addOneShotTask(exporter);
  }

  /**
   * The task that runs at the end of the analysis, for dumping the XML report
   * to the file specified in the $KIUWAN_JSON_REPORT environment variable.
   */
  public static class ReportExportTask implements OneShotTask {
    private final String report = SysUtils.getProperty("KIUWAN_JSON_REPORT");
    private final boolean isActive = StringUtil.hasText(report);

    @Override public boolean isActiveTask() { return isActive; }

    @Override public void start(RuleContext ctx) {
      if(!isActive) return;
      System.out.println(ExportRule.class.getName() + " active, will export report to: " + report);
    }

    @Override public void end(RuleContext ctx) {
      if(!isActive) return;

      File reportFile = getReportFile();

      try(OutputStream os = IOUtils.openOutputStream(reportFile, false)) {
        getRenderer().render(ctx.getReport(), os, reportFile.getParentFile(), ctx);
        System.out.println("Report file available at: " + reportFile.getAbsolutePath());

      } catch (IOException | RenderException e) {
        System.err.println("Error: cannot write report file "+ reportFile + ": " + e.getMessage());
      }
    }

    private File getReportFile() {
      File reportFile = new File(report);
      if(!reportFile.isAbsolute()) {
        // Use $HOME as base directory if relative path is provided.
        // Often $HOME is writable even on CI/CD runners.
        reportFile = new File(SysUtils.getUserHome(), report);
      }

      // ensure the directory for report exists
      // noinspection ResultOfMethodCallIgnored
      reportFile.getParentFile().mkdirs();

      return reportFile;
    }

    /** XmlIssuesRenderer with simple configuration. We do not render muted issues, but you may change this. */
    private Renderer getRenderer() {
      XmlIssuesRenderer renderer = new XmlIssuesRenderer();

      renderer.setIndentPositions(2);
      renderer.setRenderMutedIssues(false); // ignore muted
      renderer.setRenderChecks(true);
      renderer.setRenderCheckDetails(true);
      renderer.setRenderErrors(true);
      renderer.setRenderIssuesStatistics(true);

      return renderer;
    }
  }

}
