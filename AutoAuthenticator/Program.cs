using System;
using System.IO;
using Micros.LES.EGateway;
using SimphonyUtilities.Security;
using Micros.LES.EGateway.EGatewayClient;

namespace AutoAuthenticator
{
    class Program
    {
        static void Main(string[] args)
        {
            AuthenticationDetails details;

            try
            {
                details = AuthenticationDetails.LoadFromJson("AuthDetails.json");
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("Could not find AuthDetails.json.\nExiting...");
                return;
            }

            SecurityApi.Init();

            var message = Authenticate(details.EGatewayUrl, details.Username, details.DecryptedPassword, details.Organization, details.ServiceHostId, details.WorkstationServiceId);
            Console.WriteLine(message);
        }

        public static string Authenticate(string EGatewayUrl, string Username, string Password, string Organization, long ServiceHostId, long WorkstationServiceId)
        {
            CGwSecExCredentials credentails = new CGwSecExCredentials();
            credentails.mUserName = Username;
            credentails.mPasskey = Password;
            credentails.mOrganization = Organization;

            CGwSecExAuthIdentity newId = new CGwSecExAuthIdentity();
            newId.mIdType = ESecExAuthIdentityType.ServiceHost;
            newId.mId = ServiceHostId;
            newId.mIdStr = "";
            long workstationServiceId = WorkstationServiceId;
            bool isHeadless = false;
            string info = string.Empty;
            string config = string.Empty;

            if (EGatewayClientWS.InitialAuthentication(credentails, EGatewayUrl, newId, isHeadless, "AuthenticationServer", out info, out config, ref workstationServiceId))
                return "Authentication is successful.";


            string error = "Authentication failed.";
            if (info.Contains("NotAuthorized"))
                error += " Invalid credentials.";
            else if (info.Contains("CONNECTION_DOWN"))
                error += " Could not connect to the specified URL.";

            return error;
        }
    }


}
