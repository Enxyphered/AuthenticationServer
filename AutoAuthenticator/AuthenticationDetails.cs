using System.IO;
using Newtonsoft.Json;

namespace AutoAuthenticator
{
    public class AuthenticationDetails
    {
        private Security _security = new Security();

        public string EGatewayUrl { get; set; }
        public string Username { get; set; }
        public string EncyptedPassword { get; set; }
        public string Organization { get; set; }
        public long ServiceHostId { get; set; }
        public long WorkstationServiceId { get; set; }

        [JsonIgnore]
        public string DecryptedPassword { get => _security.Decrypt(EncyptedPassword); }
        public void SetPassword(string password) { EncyptedPassword = _security.Encrypt(password); }

        public static AuthenticationDetails LoadFromJson(string fileName)
        {
            var json = File.ReadAllText(fileName);
            var details = JsonConvert.DeserializeObject<AuthenticationDetails>(json);

            if (json.StartsWith("//AuthDetails"))
            {
                details.SetPassword(details.EncyptedPassword);
                var outputJson = JsonConvert.SerializeObject(details);
                File.WriteAllText(fileName, outputJson);
            }

            return details;
        }
    }
}
