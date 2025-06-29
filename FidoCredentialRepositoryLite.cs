using Fido2NetLib.Objects;
using Fido2NetLib;
using Fido2TestApi;
using System.Net;
using System.Data.SqlClient;
using System.Data;
using Fido2NetLib.Development;
using Microsoft.Data.Sqlite;

namespace Fido2TestApi
{

    public class FidoCredentialRepositoryLite
    {
        private readonly string _connectionString;

        public FidoCredentialRepositoryLite(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnectionLite");
        }

        public async Task<List<PublicKeyCredentialDescriptor>> GetUserCredentialsAsync(string userId)
        {
            var creds = new List<PublicKeyCredentialDescriptor>();
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT CredentialId FROM FidoCredentials WHERE UserId = @UserId";
            cmd.Parameters.AddWithValue("@UserId", userId);

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                var credId = Convert.FromBase64String(reader.GetString(0));
                creds.Add(new PublicKeyCredentialDescriptor(credId));
            }

            return creds;
        }

        public async Task<(byte[] publicKey, uint counter, string userId)?> GetCredentialAsync(string credentialId)
        {
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            var cmd = conn.CreateCommand();
            cmd.CommandText = @"
            SELECT PublicKey, Counter, UserId 
            FROM FidoCredentials 
            WHERE CredentialId = @CredentialId";
            cmd.Parameters.AddWithValue("@CredentialId", credentialId);

            using var reader = await cmd.ExecuteReaderAsync();
            if (!await reader.ReadAsync())
                return null;

            var publicKey = Convert.FromBase64String(reader.GetString(0));
            var counter = (uint)reader.GetInt32(1);
            var userId = reader.GetString(2);
            return (publicKey, counter, userId);
        }

        public async Task UpdateSignatureCounterAsync(string credentialId, uint counter)
        {
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE FidoCredentials SET Counter = @Counter WHERE CredentialId = @CredentialId";
            cmd.Parameters.AddWithValue("@Counter", (int)counter);
            cmd.Parameters.AddWithValue("@CredentialId", credentialId);

            await cmd.ExecuteNonQueryAsync();
        }

        public async Task<bool> CredentialExistsAsync(string credentialId)
        {
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM FidoCredentials WHERE CredentialId = @CredentialId";
            cmd.Parameters.AddWithValue("@CredentialId", credentialId);

            var count = Convert.ToInt32(await cmd.ExecuteScalarAsync());
            return count > 0;
        }

        public async Task InsertCredentialAsync(FidoRegistrationRequest request, Fido2.CredentialMakeResult result)
        {
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            var cmd = conn.CreateCommand();
            cmd.CommandText = @"
            INSERT INTO FidoCredentials 
            (UserId, CredentialId, PublicKey, Counter, Aaguid, CredType, Format, DisplayName, CreatedAt)
            VALUES (@UserId, @CredentialId, @PublicKey, @Counter, @Aaguid, @CredType, @Format, @DisplayName, @CreatedAt)";

            cmd.Parameters.AddWithValue("@UserId", request.Username);
            cmd.Parameters.AddWithValue("@CredentialId", Convert.ToBase64String(result.Result.CredentialId));
            cmd.Parameters.AddWithValue("@PublicKey", Convert.ToBase64String(result.Result.PublicKey));
            cmd.Parameters.AddWithValue("@Counter", (int)result.Result.Counter);
            cmd.Parameters.AddWithValue("@Aaguid", result.Result.Aaguid.ToString());
            cmd.Parameters.AddWithValue("@CredType", "public-key");
            cmd.Parameters.AddWithValue("@Format", "packed");
            cmd.Parameters.AddWithValue("@DisplayName", request.DisplayName);
            cmd.Parameters.AddWithValue("@CreatedAt", System.DateTime.UtcNow);

            await cmd.ExecuteNonQueryAsync();
        }

        public async Task<List<object>> GetAllPasskeysAsync()
        {
            var result = new List<object>();
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT Id, UserId, CredentialId, DisplayName, CreatedAt FROM FidoCredentials";

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                result.Add(new
                {
                    Id = reader.GetInt32(0),
                    UserId = reader.GetString(1),
                    CredentialId = reader.GetString(2),
                    DisplayName = reader.GetString(3),
                    CreatedAt = reader.GetDateTime(4)
                });
            }

            return result;
        }

        public async Task<bool> DeletePasskeyByIdAsync(int id)
        {
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM FidoCredentials WHERE Id = @Id";
            cmd.Parameters.AddWithValue("@Id", id);

            var rows = await cmd.ExecuteNonQueryAsync();
            return rows > 0;
        }
    }
}