using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using IdentityServer3.Core;
using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Services.Default;
using System.Net;
using System.DirectoryServices.Protocols;

namespace SampleApp
{
    public class LocalRegistrationUserService : UserServiceBase
    {
        public class CustomUser
        {
            public string Subject { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }
            public List<Claim> Claims { get; set; }
        }

        public static List<CustomUser> Users = new List<CustomUser>();

        public override Task AuthenticateLocalAsync(LocalAuthenticationContext context)
        {
            //var user = Users.SingleOrDefault(x => x.Username == context.UserName && x.Password == context.Password);
            //if (user != null)
            //{
            //    context.AuthenticateResult = new AuthenticateResult(user.Subject, user.Username);
            //}
            
            var credential = new NetworkCredential("uid=" + context.UserName + ",o=datakraftverk-virtual", context.Password);

            using (var con = new LdapConnection("10.48.204.77:636") { Credential = credential, AuthType = AuthType.Basic, AutoBind = false })
            {
                con.SessionOptions.ProtocolVersion = 3;
                con.SessionOptions.VerifyServerCertificate += delegate { return true; };                
                con.Bind();
                
                string filter = "(uid=" + context.UserName + ")";
                SearchRequest search = new SearchRequest("o=datakraftverk-virtual", filter, SearchScope.Subtree, "*");
                SearchResponse resp = con.SendRequest(search) as SearchResponse;
                SearchResultEntry entry = resp.Entries[0];
                                
                context.AuthenticateResult = new AuthenticateResult(context.UserName, entry.Attributes["cn"][0].ToString());

                Users.Add(new CustomUser() { Subject = context.UserName, Claims = new List<Claim>() { new Claim("email", entry.Attributes["mail"][0].ToString()), new Claim("cn", entry.Attributes["cn"][0].ToString()), new Claim("roles", "role1,role2") } });
            }
            
            return Task.FromResult(0);
        }

        public override Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            // issue the claims for the user
            //var user = Users.SingleOrDefault(x => x.Subject == context.Subject.GetSubjectId());
            //if (user != null)
            //{
            //    context.IssuedClaims = user.Claims.Where(x => context.RequestedClaimTypes.Contains(x.Type));
            //}
            
            using (var con = new LdapConnection("10.48.204.77:636") { Credential = new NetworkCredential("cn=Directory Manager", "n3wpassW0rd"), AuthType = AuthType.Basic, AutoBind = false })
            {
                con.SessionOptions.ProtocolVersion = 3;
                con.SessionOptions.VerifyServerCertificate += delegate { return true; };
                con.Bind();
                
                string filter = "(uid=" + context.Subject.GetSubjectId() + ")";
                SearchRequest search = new SearchRequest("o=datakraftverk-virtual", filter, SearchScope.Subtree, "*");
                SearchResponse resp = con.SendRequest(search) as SearchResponse;
                SearchResultEntry entry = resp.Entries[0];
                var claims = new List<Claim>();

                //  openid
                claims.Add(new Claim("sub", entry.Attributes["uid"][0].ToString()));

                //  profile
                // name, family_name, given_name, middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, and updated_at
                if (entry.Attributes.Contains("displayName")) claims.Add(new Claim("name", entry.Attributes["displayName"][0].ToString()));
                if (entry.Attributes.Contains("givenName")) claims.Add(new Claim("given_name", entry.Attributes["givenName"][0].ToString()));
                if (entry.Attributes.Contains("sn")) claims.Add(new Claim("family_name", entry.Attributes["sn"][0].ToString()));
                
                //  email scope
                if (context.RequestedClaimTypes.Contains("email"))
                    claims.Add(new Claim("email", entry.Attributes["mail"][0].ToString()));
                
                //  rest of attributes
                foreach (string attr in entry.Attributes.AttributeNames)
                    claims.Add(new Claim(attr, entry.Attributes[attr][0].ToString()));
                
                // roles scope
                if (context.RequestedClaimTypes.Contains("role"))
                {
                    filter = "(uniqueMember=uid=" + context.Subject.GetSubjectId() + ",o=datakraftverk-virtual)";
                    search = new SearchRequest("o=ids-groups", filter, SearchScope.Subtree, "*");
                    resp = con.SendRequest(search) as SearchResponse;
                    
                    foreach(SearchResultEntry group in resp.Entries)
                        claims.Add(new Claim("role", group.Attributes["cn"][0].ToString()));                    
                }
                context.IssuedClaims = claims.Where(x => context.RequestedClaimTypes.Contains(x.Type));
            }

            return Task.FromResult(0);
        }
    }
}
