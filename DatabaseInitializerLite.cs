using Microsoft.Data.Sqlite;

namespace Fido2TestApi
{
public static class DatabaseInitializerLite
{
    public static void Initialize(string connectionString)
    {
        using var connection = new SqliteConnection(connectionString);
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = @"
            CREATE TABLE IF NOT EXISTS FidoCredentials (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                UserId TEXT NOT NULL,
                CredentialId TEXT NOT NULL,
                PublicKey TEXT NOT NULL,
                Counter INTEGER NOT NULL,
                Aaguid TEXT NOT NULL,
                CredType TEXT NOT NULL,
                Format TEXT NOT NULL,
                DisplayName TEXT NOT NULL,
                CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        ";

        command.ExecuteNonQuery();
    }
}

}
