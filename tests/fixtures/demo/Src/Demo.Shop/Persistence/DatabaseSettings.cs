using System.Configuration;

namespace Demo.Shop.Persistence
{
    public static class DatabaseSettings
    {
        public static string ConnectionString
        {
            get { return ConfigurationManager.ConnectionStrings["Shop"].ConnectionString; }
        }
    }
}
