﻿using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Sample;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Net;
using System.Security.Claims;
//using System.Security.Claims;
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
                    ClientId = "mvc.owin.hybrid",
                    Authority = Constants.BaseAddress,
                    RedirectUri = "https://connect.acc.prov.testaws.visma.net/mvchybrid/",
                    PostLogoutRedirectUri = "https://connect.acc.prov.testaws.visma.net/mvchybrid/",
                    ResponseType = "code id_token",
                    Scope = "openid profile read write offline_access",
                    
                    SignInAsAuthenticationType = "Cookies",

                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        SecurityTokenValidated = n =>
                        {
                            var id = n.AuthenticationTicket.Identity;

                            // we want to keep first name, last name, subject and roles
                            var name = id.FindFirst(ClaimTypes.Name);
                            var roles = id.FindAll(ClaimTypes.Role);
                            
                            // create new identity and set name and role claim type
                            var nid = new ClaimsIdentity(
                                id.AuthenticationType,
                                ClaimTypes.GivenName,
                                ClaimTypes.Role);

                            nid.AddClaim(name);
                            nid.AddClaims(roles);

                            // add some other app specific claim
                            nid.AddClaim(new Claim("app_specific", "some data"));
                            nid.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));

                            n.AuthenticationTicket = new AuthenticationTicket(
                                nid,
                                n.AuthenticationTicket.Properties);

                            return Task.FromResult(0);
                        },

                        AuthorizationCodeReceived = async n =>
                        {
                            // use the code to get the access and refresh token
                            var tokenClient = new TokenClient(
                                Constants.TokenEndpoint,
                                "mvc.owin.hybrid",
                                "secret");

                            var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(
                                n.Code, n.RedirectUri);

                            // use the access token to retrieve claims from userinfo
                            var userInfoClient = new UserInfoClient(
                                new Uri(Constants.UserInfoEndpoint),
                                tokenResponse.AccessToken);

                            var userInfoResponse = await userInfoClient.GetAsync();
                                
                            // create new identity
                            var id = new ClaimsIdentity(n.AuthenticationTicket.Identity.AuthenticationType);
                            id.AddClaims(userInfoResponse.GetClaimsIdentity().Claims);

                            id.AddClaim(new Claim("access_token", tokenResponse.AccessToken));
                            id.AddClaim(new Claim("expires_at", DateTime.Now.AddSeconds(tokenResponse.ExpiresIn).ToLocalTime().ToString()));
                            id.AddClaim(new Claim("refresh_token", tokenResponse.RefreshToken));
                            id.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));
                            id.AddClaim(new Claim("sid", n.AuthenticationTicket.Identity.FindFirst("sid").Value));

                            n.AuthenticationTicket = new AuthenticationTicket(
                                new ClaimsIdentity(id.Claims, n.AuthenticationTicket.Identity.AuthenticationType),
                                n.AuthenticationTicket.Properties);
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