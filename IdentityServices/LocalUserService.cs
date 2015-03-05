using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Thinktecture.IdentityServer.Core.Models;
using Thinktecture.IdentityServer.Core.Services;
using Thinktecture.IdentityServer.Core.Extensions;
using Thinktecture.IdentityServer.Core;
using Thinktecture.IdentityServer.Core.Services.InMemory;

namespace IdentityServices
{
    public class LocalUserService : IUserService
    {
        public class SLUser : InMemoryUser
        {
            //public string Subject { get; set; }
            //public string UserName { get; set; }
            //public string Password { get; set; }
            //public List<Claim> Claims { get; set; }
        }

        public static List<SLUser> Users = new List<SLUser>();

        public LocalUserService()
        {
            if (!Users.Any(a => a.Username == "bob"))
            {
                SLUser _user = new SLUser() { Subject = "Manually Created User", Username = "bob", Password = "secret" };
                
                _user.Claims = new[]
                    {
                        new Claim(Constants.ClaimTypes.GivenName, "Bob"),
                        new Claim(Constants.ClaimTypes.FamilyName, "Smith"),
                        new Claim(Constants.ClaimTypes.Role, "Geek"),
                        new Claim(Constants.ClaimTypes.Role, "Foo")
                    };

                Users.Add(_user);

                // For MVC Authentication sample
                
            }
        }

        public Task<AuthenticateResult> PreAuthenticateAsync(Thinktecture.IdentityServer.Core.Models.SignInMessage message)
        {
            return Task.FromResult<AuthenticateResult>(null);
        }

        public Task<AuthenticateResult> AuthenticateLocalAsync(string username, string password, SignInMessage message)
        {
            var user = Users.SingleOrDefault(x => x.Username == username && x.Password == password);
            if (user == null)
            {
                return Task.FromResult<AuthenticateResult>(null);
            }

            return Task.FromResult<AuthenticateResult>(new AuthenticateResult(user.Subject, user.Username));
        }

        public Task<AuthenticateResult> AuthenticateExternalAsync(ExternalIdentity externalUser, SignInMessage message)
        {
            return Task.FromResult<AuthenticateResult>(null);
        }

        public Task SignOutAsync(ClaimsPrincipal subject)
        {
            return Task.FromResult(0);
        }

        public Task<IEnumerable<Claim>> GetProfileDataAsync(ClaimsPrincipal subject, IEnumerable<string> requestedClaimTypes = null)
        {
            // issue the claims for the user
            var user = Users.SingleOrDefault(x => x.Subject == subject.GetSubjectId());
            if (user == null)
            {
                return Task.FromResult<IEnumerable<Claim>>(null);
            }

            return Task.FromResult(user.Claims.Where(x => requestedClaimTypes.Contains(x.Type)));
        }

        public Task<bool> IsActiveAsync(ClaimsPrincipal subject)
        {
            var user = Users.SingleOrDefault(x => x.Subject == subject.GetSubjectId());
            return Task.FromResult(user != null);
        }
    }
}
