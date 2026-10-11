using System;

namespace Demo.Shop.Services
{
    public class ReportService
    {
        public string Render(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new Exception("Nome del report mancante");
            }
            return name.Trim();
        }
    }
}
