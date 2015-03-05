﻿using Microsoft.Owin;
using Owin;
using System.Web.Http;
using Thinktecture.IdentityServer.AccessTokenValidation;

[assembly: OwinStartup(typeof(IdentityWebApis.Startup))]

namespace IdentityWebApis
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // accept access tokens from identityserver and require a scope of 'api1'
            app.UseIdentityServerBearerTokenAuthentication(new IdentityServerBearerTokenAuthenticationOptions
                {
                    Authority = "https://localhost/IdSvr/Core",
                    RequiredScopes = new[] { "api1" }
                });

            // configure web api
            var config = new HttpConfiguration();
            config.MapHttpAttributeRoutes();

            // require authentication for all controllers
            config.Filters.Add(new AuthorizeAttribute());

            app.UseWebApi(config);
        }
    }
}