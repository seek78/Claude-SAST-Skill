using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;

namespace Demo.Shop.Persistence
{
    public class OrderRepository
    {
        private readonly string connectionString = DatabaseSettings.ConnectionString;

        public IList<string> Find(string term)
        {
            using (var connection = new SqlConnection(connectionString))
            using (IDbCommand command = connection.CreateCommand())
            {
                // La ricerca compone il testo SQL con il termine ricevuto dall'utente.
                command.CommandText = string.Format("SELECT Code FROM Orders WHERE Description LIKE '%{0}%'", term);
                connection.Open();
                return Read(command);
            }
        }

        public IList<string> FindById(int id)
        {
            using (var connection = new SqlConnection(connectionString))
            using (IDbCommand command = connection.CreateCommand())
            {
                command.CommandText = string.Format("SELECT Code FROM Orders WHERE Id = {0}", id);
                connection.Open();
                return Read(command);
            }
        }

        private static IList<string> Read(IDbCommand command)
        {
            var codes = new List<string>();
            using (IDataReader reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    codes.Add(reader.GetString(0));
                }
            }
            return codes;
        }
    }
}
