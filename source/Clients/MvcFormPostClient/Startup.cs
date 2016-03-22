using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Net;

namespace MvcFormPostClient
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
                {
                    AuthenticationType = "Cookies"
                });


            app.UseCookieAuthentication(new CookieAuthenticationOptions
                {
                    AuthenticationType = "TempCookie",
                    AuthenticationMode = AuthenticationMode.Passive
                });
        }
    }
}