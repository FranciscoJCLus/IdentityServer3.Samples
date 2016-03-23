using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Sample;
using System.Collections.Generic;
//using System.IdentityModel.Claims;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Threading.Tasks;

[assembly: OwinStartup(typeof(MVC_OWIN_Client.Startup))]

namespace MVC_OWIN_Client
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies"
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = "mvc.owin.implicit",
                Authority = Constants.BaseAddress,
                RedirectUri = "https://connect.acc.prov.testaws.visma.net/mvcimplicit/Home/Claims",
                ResponseType = "id_token",
                Scope = "openid email profile roles",

                UseTokenLifetime = false,
                SignInAsAuthenticationType = "Cookies",
                                
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = n =>
                    {
                        var id = n.AuthenticationTicket.Identity;
                        
                        var nid = new ClaimsIdentity(id.AuthenticationType);
                        nid.AddClaims(id.Claims);

                        // add some other app specific claim
                        nid.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));

                        n.AuthenticationTicket = new AuthenticationTicket(
                            nid,
                            n.AuthenticationTicket.Properties);

                        return Task.FromResult(0);
                    },
                    RedirectToIdentityProvider = n =>
                    {
                        // if signing out, add the id_token_hint
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
                        {
                            var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");
                            if (idTokenHint != null)
                            {
                                n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                            }
                        }

                        return Task.FromResult(0);
                    }
                }
            });
        }
    }
}