/*
 * Copyright 2014, 2015 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Thinktecture.IdentityServer.Core;
using Thinktecture.IdentityServer.Core.Extensions;
using Thinktecture.IdentityServer.Core.Logging;
using Thinktecture.IdentityServer.Core.Models;
using Thinktecture.IdentityServer.Core.Services;
using Thinktecture.IdentityServer.Core.Validation;

namespace IdentityServices
{
    public class LocalClaimsProvider : IClaimsProvider
    {
        /// <summary>
        /// The logger
        /// </summary>
        protected readonly static ILog Logger = LogProvider.GetCurrentClassLogger();

        /// <summary>
        /// The user service
        /// </summary>
        protected readonly IUserService _users;

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultClaimsProvider"/> class.
        /// </summary>
        /// <param name="users">The users service</param>
        public LocalClaimsProvider(IUserService users)
        {
            _users = users;
        }

        /// <summary>
        /// Returns claims for an identity token
        /// </summary>
        /// <param name="subject">The subject</param>
        /// <param name="client">The client</param>
        /// <param name="scopes">The requested scopes</param>
        /// <param name="includeAllIdentityClaims">Specifies if all claims should be included in the token, or if the userinfo endpoint can be used to retrieve them</param>
        /// <param name="request">The raw request</param>
        /// <returns>
        /// Claims for the identity token
        /// </returns>

        public virtual async Task<IEnumerable<Claim>> GetIdentityTokenClaimsAsync(ClaimsPrincipal subject, Client client, IEnumerable<Scope> scopes, bool includeAllIdentityClaims, Thinktecture.IdentityServer.Core.Validation.ValidatedRequest request)
        {
            Logger.Info("Getting claims for identity token for subject: " + subject.GetSubjectId());

            var outputClaims = new List<Claim>(GetStandardSubjectClaims(subject));
            outputClaims.AddRange(GetOptionalClaims(subject));

            var additionalClaims = new List<string>();

            //// if a include all claims rule exists, call the user service without a claims filter
            //if (scopes.IncludesAllClaimsForUserRule(ScopeType.Identity))
            //{
            //    Logger.Info("All claims rule found - emitting all claims for user.");

            //    var claims = await _users.GetProfileDataAsync(subject);
            //    if (claims != null)
            //    {
            //        outputClaims.AddRange(claims);
            //    }

            //    return outputClaims;
            //}

            // fetch all identity claims that need to go into the id token
            foreach (var scope in scopes)
            {
                if (scope.Type == ScopeType.Identity)
                {
                    foreach (var scopeClaim in scope.Claims)
                    {
                        if (includeAllIdentityClaims || scopeClaim.AlwaysIncludeInIdToken)
                        {
                            additionalClaims.Add(scopeClaim.Name);
                        }
                    }
                }
            }

            if (additionalClaims.Count > 0)
            {
                var claims = await _users.GetProfileDataAsync(subject, additionalClaims);
                if (claims != null)
                {
                    outputClaims.AddRange(claims);
                }
            }

            // Code here gets all our custom claims

            outputClaims.AddRange(GetUserClaims(subject));

            return outputClaims;
        }

        /// <summary>
        /// Returns claims for an identity token.
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <param name="client">The client.</param>
        /// <param name="scopes">The requested scopes.</param>
        /// <param name="request">The raw request.</param>
        /// <returns>
        /// Claims for the access token
        /// </returns>
        /// 
        public virtual async Task<IEnumerable<Claim>> GetAccessTokenClaimsAsync(System.Security.Claims.ClaimsPrincipal subject, Thinktecture.IdentityServer.Core.Models.Client client, IEnumerable<Thinktecture.IdentityServer.Core.Models.Scope> scopes, Thinktecture.IdentityServer.Core.Validation.ValidatedRequest request)
        {
            // add client_id
            var outputClaims = new List<Claim>
            {
                new Claim(Constants.ClaimTypes.ClientId, client.ClientId),
            };

            // check for client claims
            if (client.Claims != null && client.Claims.Any())
            {
                if (subject == null || client.AlwaysSendClientClaims)
                {
                    foreach (var claim in client.Claims)
                    {
                        var claimType = claim.Type;

                        if (client.PrefixClientClaims)
                        {
                            claimType = "client_" + claimType;
                        }

                        outputClaims.Add(new Claim(claimType, claim.Value, claim.ValueType));
                    }
                }
            }

            // add scopes
            foreach (var scope in scopes)
            {
                outputClaims.Add(new Claim(Constants.ClaimTypes.Scope, scope.Name));
            }

            // a user is involved
            if (subject != null)
            {
                outputClaims.AddRange(GetStandardSubjectClaims(subject));
                outputClaims.AddRange(GetOptionalClaims(subject));

                // if a include all claims rule exists, call the user service without a claims filter
                if (scopes.IncludesAllClaimsForUserRule(ScopeType.Resource))
                {
                    var claims = await _users.GetProfileDataAsync(subject);
                    if (claims != null)
                    {
                        outputClaims.AddRange(claims);
                    }

                    return outputClaims;
                }


                // fetch all resource claims that need to go into the id token
                var additionalClaims = new List<string>();
                foreach (var scope in scopes)
                {
                    if (scope.Type == ScopeType.Resource)
                    {
                        if (scope.Claims != null)
                        {
                            foreach (var scopeClaim in scope.Claims)
                            {
                                additionalClaims.Add(scopeClaim.Name);
                            }
                        }
                    }
                }

                if (additionalClaims.Count > 0)
                {
                    var claims = await _users.GetProfileDataAsync(subject, additionalClaims.Distinct());
                    if (claims != null)
                    {
                        outputClaims.AddRange(claims);
                    }
                }
            }

            outputClaims.AddRange(GetUserClaims(subject));

            return outputClaims;
        }

         /// <summary>
        /// Gets the standard subject claims.
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <returns>A list of standard claims</returns>
        protected virtual IEnumerable<Claim> GetStandardSubjectClaims(ClaimsPrincipal subject)
        {
            var claims = new List<Claim>
            {
                new Claim(Constants.ClaimTypes.Subject, subject.GetSubjectId()),
                new Claim(Constants.ClaimTypes.AuthenticationMethod, subject.GetAuthenticationMethod()),
                new Claim(Constants.ClaimTypes.AuthenticationTime, subject.GetAuthenticationTimeEpoch().ToString(), ClaimValueTypes.Integer),
                new Claim(Constants.ClaimTypes.IdentityProvider, subject.GetIdentityProvider()),
            };

            return claims;
        }

        /// <summary>
        /// Gets additional (and optional) claims from the cookie or incoming subject.
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <returns>Additional claims</returns>
        protected virtual IEnumerable<Claim> GetOptionalClaims(ClaimsPrincipal subject)
        {
            var claims = new List<Claim>();

            var acr = subject.FindFirst(Constants.ClaimTypes.AuthenticationContextClassReference);
            if (acr.HasValue()) claims.Add(acr);

            return claims;
        }
    
        /// <summary>
        /// Get Claims for user
        /// </summary>
        /// <param name="subject"></param>
        /// <returns></returns>
        protected virtual IEnumerable<Claim> GetUserClaims(ClaimsPrincipal subject)
        {
            var _ret = new List<Claim>();

            // Code here gets all our custom claims

            Claim _newClaim = new Claim("ApiFullRights", "true");
            Claim _newNameIdentifier = new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", "bsmith");
            _ret.Add(_newClaim);
            _ret.Add(_newNameIdentifier);

            return _ret;
        }
    }
}