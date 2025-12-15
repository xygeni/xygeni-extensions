using System.Diagnostics;
using System.Web;
using System.IO;

namespace Example
{
    public class CommandInjectionVulnerable : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            Stream requestBody = Request.GetBufferedInputStream(); // source
            if (requestBody == null) return;

            StreamReader reader = new StreamReader(requestBody);
            string cmd = "echo";
            string args = reader.ReadToEnd();
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = cmd;
            startInfo.Arguments = args; // FLAW
            Process.Start(startInfo);
        }
    }
}
