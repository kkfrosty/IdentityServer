using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IdentityModel.Selectors;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Configuration;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.Text;
using System.Web;

namespace WCFJWTServices
{
    public class BearerTokenMessageInspector : IDispatchMessageInspector
    {
        string _identityServerUrl = "";

        public BearerTokenMessageInspector()
        {
            _identityServerUrl = ConfigurationManager.AppSettings["IdentityServerUrl"];
        }

        public object AfterReceiveRequest(ref System.ServiceModel.Channels.Message request, System.ServiceModel.IClientChannel channel, System.ServiceModel.InstanceContext instanceContext)
        {
            object correlationState = null;

            HttpRequestMessageProperty requestMessage = request.Properties["httpRequest"] as HttpRequestMessageProperty;
            if (request == null)
            {
                throw new InvalidOperationException("Invalid request type.");
            }
            string authHeader = requestMessage.Headers["Authorization"];

            if (string.IsNullOrEmpty(authHeader) || !Authenicate(OperationContext.Current.IncomingMessageHeaders.To.AbsoluteUri, requestMessage.Method, authHeader))
            {
                WcfErrorResponseData error = new WcfErrorResponseData(HttpStatusCode.Forbidden);
                correlationState = error;
                request = null;
            }

            return correlationState;
        }

        private bool Authenicate(string resourceName, string action, string authHeader)
        {


            const string bearer = "Bearer ";
            if (authHeader.StartsWith(bearer, StringComparison.InvariantCultureIgnoreCase))
            {
                string tokenString = authHeader.Substring(bearer.Length);

                // This code will valid the AccessToken if it's of type JWT.  If valid
                // A claimsprincipal will be created which will provide both authentication & Authorization for wcf services
                if (FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.CanReadToken(tokenString))
                {
                    TokenValidationParameters _validationParameters = CreateTokenValidationParameters();

                    // Claims etc can be read from token but need to validate inorder to build a Claims Principal
                    //  var _securityToken = FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.ReadToken(tokenString);

                    // This code can be used to pull back the certificate used if the WCF service is using the same certificate has the Identity Server web
                    // host.  However, dynamically pull this using the x5c from Idenity Server
                    // Can be retrieved dynamically x5c from /core/.well-known/jwks
                    //   var _509Cert2 = GetX509Certificate("CN=localhost, OU=Dev, O=Company, L=City, S=state, C=US");
                    //   var _509SecurityToken = new X509SecurityToken(_509Cert2);

                    SecurityToken _securityToken = null;

                    JwtSecurityTokenHandler _tokenHandler = new JwtSecurityTokenHandler();

                    // Next call will throw the exception if the token or configuration is not valid
                    // var identities = FederatedAuthentication.FederationConfiguration.IdentityConfiguration.SecurityTokenHandlers.ValidateToken(tokenString, _validationParameters, out _securityToken);
                    var _claimsPrincipal = _tokenHandler.ValidateToken(tokenString, _validationParameters, out _securityToken);
                    //     var claimsPrincipal = new ClaimsPrincipal(_identities.First());
                    // Additionally, we need to ensure that ClaimsAuthenticationManager is invoked.
                    _claimsPrincipal = FederatedAuthentication.FederationConfiguration.IdentityConfiguration.ClaimsAuthenticationManager.Authenticate(resourceName, _claimsPrincipal);
                    // Override identity on the current operation so the developer get nice access to current principal
                    // This is somewhat of a hack since it is relying on internal knowledge of how WIF and WCF will process incoming token
                    ServiceSecurityContext.Current.AuthorizationContext.Properties["ClaimsPrincipal"] = _claimsPrincipal;
                    ServiceSecurityContext.Current.AuthorizationContext.Properties["Identities"] = _claimsPrincipal.Identities;

                    // And finally make sure we're actuall authorized to access this resource
                    var autorizationContext = new AuthorizationContext(_claimsPrincipal, resourceName, action);
                    return FederatedAuthentication.FederationConfiguration.IdentityConfiguration.ClaimsAuthorizationManager.CheckAccess(autorizationContext);
                }
            }
            return false;
        }

        // Requires Nuget-package System.IdentityModel.Tokens.Jwt
        private TokenValidationParameters CreateTokenValidationParameters()
        {
            //Can be retrieved dynamically x5c from /core/.well-known/jwks
            // Depending on performance, we may want to put the x5c value in config versus making a call to get it
            // every single time a wcf service call is made.
            HttpClient _client = new HttpClient();
            // Get Json Web Key from Identity Server
            string _jwks = _client.GetStringAsync(string.Format("{0}/core/.well-known/jwks", _identityServerUrl)).Result;

            // Parse as Json Object so it can be read
            JObject _jObject = JObject.Parse(_jwks);

            // The return value is a keys array with one element
            var _x5cArray = _jObject["keys"][0]["x5c"];

            // For some reason, the xc5 is stored as an array so the first element must be used to get the xc5 value 
            // from the certificate
            string _x5c = (string)_x5cArray[0];

            var rawData = Encoding.UTF8.GetBytes(_x5c);
            var x509Certificate2 = new X509Certificate2(rawData);
            var x509SecurityToken = new X509SecurityToken(x509Certificate2);

            var parameters = new TokenValidationParameters
            {
                ValidAudience = string.Format("{0}/resources", _identityServerUrl),
                ValidIssuer = _identityServerUrl,
                IssuerSigningToken = x509SecurityToken
            };

            return parameters;
        }

        /// <summary>
        /// Used to pull back a 509 certificate by subject name.
        /// </summary>
        /// <param name="subjectName"></param>
        /// <returns></returns>
        public X509Certificate2 GetX509Certificate(string subjectName)
        {
            X509Store certificateStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            certificateStore.Open(OpenFlags.ReadOnly);
            X509Certificate2 certificate;

            try
            {
                certificate = certificateStore.Certificates.OfType<X509Certificate2>().
                                                              FirstOrDefault(cert => cert.SubjectName.Name.Equals(subjectName, StringComparison.OrdinalIgnoreCase));
            }
            finally
            {
                certificateStore.Close();
            }

            if (certificate == null)
            {
                //   StringBuilder
                throw new Exception(String.Format("Certificate '{0}' not found.", subjectName));
            }


            return certificate;
        }

        public void BeforeSendReply(ref System.ServiceModel.Channels.Message reply, object correlationState)
        {
            WcfErrorResponseData error = correlationState as WcfErrorResponseData;
            if (error != null)
            {
                HttpResponseMessageProperty responseProperty = new HttpResponseMessageProperty();
                reply.Properties["httpResponse"] = responseProperty;
                responseProperty.StatusCode = error.StatusCode;

                IList<KeyValuePair<string, string>> headers = error.Headers;
                if (headers != null)
                {
                    for (int i = 0; i < headers.Count; i++)
                    {
                        responseProperty.Headers.Add(headers[i].Key, headers[i].Value);
                    }
                }
            }
        }
    }

    public class BearerTokenServiceBehavior : IServiceBehavior
    {
        public BearerTokenServiceBehavior()
        {

        }

        public void AddBindingParameters(ServiceDescription serviceDescription, System.ServiceModel.ServiceHostBase serviceHostBase, System.Collections.ObjectModel.Collection<ServiceEndpoint> endpoints, System.ServiceModel.Channels.BindingParameterCollection bindingParameters)
        {
            // no-op
        }

        public void ApplyDispatchBehavior(ServiceDescription serviceDescription, System.ServiceModel.ServiceHostBase serviceHostBase)
        {
            foreach (ChannelDispatcher chDisp in serviceHostBase.ChannelDispatchers)
            {
                foreach (EndpointDispatcher epDisp in chDisp.Endpoints)
                {
                    epDisp.DispatchRuntime.MessageInspectors.Add(new BearerTokenMessageInspector());
                }
            }
        }

        public void Validate(ServiceDescription serviceDescription, System.ServiceModel.ServiceHostBase serviceHostBase)
        {
            // no-op
        }
    }

    public class BearerTokenExtensionElement : BehaviorExtensionElement
    {
        public override Type BehaviorType
        {
            get { return typeof(BearerTokenServiceBehavior); }
        }

        protected override object CreateBehavior()
        {
            return new BearerTokenServiceBehavior();
        }
    }

    internal class WcfErrorResponseData
    {
        public WcfErrorResponseData(HttpStatusCode status)
            : this(status, string.Empty, null)
        {
        }
        public WcfErrorResponseData(HttpStatusCode status, string body)
            : this(status, body, null)
        {
        }
        public WcfErrorResponseData(HttpStatusCode status, string body, params KeyValuePair<string, string>[] headers)
        {
            StatusCode = status;
            Body = body;
            Headers = headers;
        }


        public HttpStatusCode StatusCode
        {
            private set;
            get;
        }

        public string Body
        {
            private set;
            get;
        }

        public IList<KeyValuePair<string, string>> Headers
        {
            private set;
            get;
        }



    }

}