using System.IO;
using System.Web.Mvc;

namespace Demo.Shop.Web
{
    public class ReportController : Controller
    {
        private const string ReportFolder = @"D:\reports\";

        // GET /report/download?name=...
        public ActionResult Download(string name)
        {
            var path = Path.Combine(ReportFolder, name);
            return File(System.IO.File.ReadAllBytes(path), "application/pdf");
        }
    }
}
