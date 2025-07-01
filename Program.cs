
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.Net;
using System.Text;
using System.Text.Json;
using Newtonsoft.Json;
using JsonSerializer = System.Text.Json.JsonSerializer;

//fido2-test.npdigateway-za1-np.kob.dell.com  --> fido2-test-web.onrender.com:4200
namespace Fido2TestApi
{


    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services
            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();
            builder.Services.AddMemoryCache();
            builder.Services.AddDistributedMemoryCache();
            builder.Services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(10);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
            });

            #region cors
            builder.Services.AddCors(options =>
            {
                options.AddDefaultPolicy(policy =>
                {
                    policy
                        .WithOrigins(
                            "https://fido2-test-web.onrender.com")
                        .AllowAnyHeader()
                        .AllowAnyMethod()
                        .AllowCredentials();
                });
            });

            #endregion
            builder.Services.Configure<Fido2Configuration>(builder.Configuration.GetSection("Fido2"));
            builder.Services.AddSingleton(provider =>
            {
                var config = provider.GetRequiredService<IOptions<Fido2Configuration>>().Value;
                return new Fido2(config);
            });

            builder.Services.AddScoped<ChallengeService>();
            builder.Services.AddScoped<FidoCredentialRepository>();
            builder.Services.AddScoped<FidoCredentialRepositoryLite>();


            #region FIDO2 RPID registration
            //https://fido2-test-web.onrender.com/.well-known/webauthn 
            var fido2 = new Fido2(new Fido2Configuration
            {//https://fido2-test-web.onrender.com/
                ServerDomain = "fido2-test-web.onrender.com",
                ServerName = "FIDO2 Demo",
                Origins = new HashSet<string>() { "https://fido2-test-web.onrender.com" }
            });
            builder.Services.AddSingleton(fido2);
            #endregion

            #region localhost certificate
            builder.WebHost.ConfigureKestrel(serverOptions =>
            {
                serverOptions.ListenAnyIP( 8080); // Listen on 0.0.0.0:8080 for Render
            });

            #endregion

            var app = builder.Build();

            // Initialize database at startup
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnectionLite");
            DatabaseInitializerLite.Initialize(connectionString);

            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseCors();
            app.UseRouting();
            app.UseSession();
            app.UseAuthorization();

            app.MapPost("/makeCredentialOptions", async (
                Fido2 fido2,
                FidoCredentialRepository repo,
                FidoCredentialRepositoryLite repoLite,
                ChallengeService challengeService,
                [FromBody] CredentialCreateRequestBody body) =>
            {
                var user = new Fido2User
                {
                    DisplayName = body.DisplayName,
                    Name = body.Username,
                    Id = Encoding.UTF8.GetBytes(body.Username)
                };

                // Lookup any existing credentials
                var existingCreds = await repoLite.GetUserCredentialsAsync(body.Username);

                // Generate options
                var options = fido2.RequestNewCredential(
                    user,
                    existingCreds,
                    AuthenticatorSelection.Default,
                    AttestationConveyancePreference.Direct
                );

                challengeService.Set("fido2.challenge", Convert.ToBase64String(options.Challenge));
                // Serialize options to JSON
                var json = JsonSerializer.Serialize(
                    options,
                    new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }
                );

                // Inject "residentKey": "preferred" into authenticatorSelection block
                json = json.Replace(
                    "\"authenticatorSelection\":{",
                    "\"authenticatorSelection\":{\"residentKey\":\"preferred\","
                );

                // Return the modified JSON
                return Results.Content(json, "application/json");
            });


            app.MapPost("/makeCredential", async (
                Fido2 fido2,
                ChallengeService challengeService,
                FidoCredentialRepository repo,
                FidoCredentialRepositoryLite repoLite,
                [FromBody] FidoRegistrationRequest request) =>
            {
                var challenge = challengeService.Get("fido2.challenge") ?? throw new InvalidOperationException("No challenge in session");

                var options = new CredentialCreateOptions
                {
                    Challenge = Convert.FromBase64String(challenge),
                    Rp = new PublicKeyCredentialRpEntity("fido2-test-web.onrender.com", "FIDO2 Demo", null),
                    User = new Fido2User
                    {
                        Id = Encoding.UTF8.GetBytes(request.Username),
                        Name = request.Username,
                        DisplayName = request.DisplayName
                    }
                };
                request.AttestationResponse =
                    JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(request
                        .Attestation.GetRawText());
                var result = await fido2.MakeNewCredentialAsync(request.AttestationResponse, options, (args, ct) => Task.FromResult(true));
                var credentialId = Convert.ToBase64String(result.Result.CredentialId);

                if (await repoLite.CredentialExistsAsync(credentialId))
                    return Results.BadRequest("This security key is already registered.");

                await repoLite.InsertCredentialAsync(request, result);
                return Results.Json(new
                {
                    CredentialId = Convert.ToBase64String(result.Result.CredentialId),
                    PublicKey = Convert.ToBase64String(result.Result.PublicKey),
                    Counter = result.Result.Counter,
                    Aaguid = result.Result.Aaguid.ToString(),
                    CredType = result.Result.CredType
                });
            });

            app.MapPost("/assertionOptions", async (
                Fido2 fido2,
                FidoCredentialRepository repo,
                FidoCredentialRepositoryLite repoLite,
                ChallengeService challengeService,
                [FromBody] FidoLoginBeginRequest request) =>
            {
                var userCreds = await repoLite.GetUserCredentialsAsync(request.Username);
                if (!userCreds.Any()) return Results.BadRequest("No credentials found for this user");

                var options = fido2.GetAssertionOptions(userCreds, UserVerificationRequirement.Required);
                challengeService.Set("fido2.assertion.challenge", Convert.ToBase64String(options.Challenge));
                challengeService.Set("fido2.assertion.username", request.Username);

                return Results.Json(options);
            });

            app.MapPost("/makeAssertion", async (
                Fido2 fido2,
                FidoCredentialRepository repo,
                FidoCredentialRepositoryLite repoLite,
                ChallengeService challengeService,
                [FromBody] FidoLoginFinishRequest request) =>
            {
                var challenge = challengeService.Get("fido2.assertion.challenge") ?? "Y2hhbGxlbmdl";
                var username = challengeService.Get("fido2.assertion.username") ?? "Y2hhbGxlbmdl";
                if (string.IsNullOrEmpty(challenge) || string.IsNullOrEmpty(username))
                    return Results.BadRequest("Missing session data");

                var credential = await repoLite.GetCredentialAsync(request.Id);
                if (credential == null) return Results.BadRequest("Credential not found");

                var (storedPublicKey, storedCounter, storedUserId) = credential.Value;
                var assertionOptions = fido2.GetAssertionOptions(
                    new List<PublicKeyCredentialDescriptor> { new(Convert.FromBase64String(request.Id)) },
                    UserVerificationRequirement.Preferred
                );
                assertionOptions.Challenge = Convert.FromBase64String(challenge);

                var assertionRaw = new AuthenticatorAssertionRawResponse
                {
                    Id = Convert.FromBase64String(request.Id),
                    RawId = Convert.FromBase64String(request.RawId),
                    Type = Enum.Parse<PublicKeyCredentialType>(request.Type.Replace("-", ""), ignoreCase: true),
                    Response = new AuthenticatorAssertionRawResponse.AssertionResponse
                    {
                        ClientDataJson = Convert.FromBase64String(request.Response.ClientDataJSON),
                        AuthenticatorData = Convert.FromBase64String(request.Response.AuthenticatorData),
                        Signature = Convert.FromBase64String(request.Response.Signature),
                        UserHandle = string.IsNullOrEmpty(request.Response.UserHandle) ? null : Convert.FromBase64String(request.Response.UserHandle)
                    }
                };

                var result = await fido2.MakeAssertionAsync(assertionRaw, assertionOptions, storedPublicKey, storedCounter, (args, ct) => Task.FromResult(true));
                await repoLite.UpdateSignatureCounterAsync(request.Id, result.Counter);

                return Results.Json(new { status = "ok", username = storedUserId });
            });

            app.MapGet("/passkeys", async (FidoCredentialRepository repo, FidoCredentialRepositoryLite repoLite) =>
            {
                var result = await repoLite.GetAllPasskeysAsync();
                return Results.Json(result);
            });

            app.MapDelete("/passkeys/{id:int}", async (int id, FidoCredentialRepository repo, FidoCredentialRepositoryLite repoLite) =>
            {
                var success = await repoLite.DeletePasskeyByIdAsync(id);
                return success ? Results.Ok(new { deleted = true }) : Results.NotFound(new { message = "Passkey not found." });
            });

            app.MapGet("/health", () => "Healthy");

            app.Run();
        }

    }

    public class CredentialCreateRequestBody
    {
        public string Username { get; set; }
        public string DisplayName { get; set; }
    }

    public class FidoRegistrationRequest
    {
        public string Username { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public JsonElement Attestation { get; set; } = default!;
        public AuthenticatorAttestationRawResponse AttestationResponse { get; set; } = default!;
    }

    public class FidoLoginBeginRequest
    {
        public string Username { get; set; } = string.Empty;
    }

    public class FidoLoginFinishRequest
    {
        public string Id { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string RawId { get; set; } = string.Empty;
        public AssertionResponse Response { get; set; } = new AssertionResponse();
    }

    public class AssertionResponse
    {
        public string AuthenticatorData { get; set; } = string.Empty;
        public string ClientDataJSON { get; set; } = string.Empty;
        public string Signature { get; set; } = string.Empty;
        public string? UserHandle { get; set; } = null;
    }

    public class ChallengeService(IMemoryCache cache)
    {
        public void Set(string key, string challenge)
        {
            cache.Set(key, challenge, TimeSpan.FromMinutes(5)); // expires in 5 min
        }

        public string? Get(string key)
        {
            cache.TryGetValue(key, out string challenge);
            return challenge;
        }
    }

}
