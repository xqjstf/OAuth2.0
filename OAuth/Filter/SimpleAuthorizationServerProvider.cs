using Microsoft.Owin.Security.OAuth;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using System.Security.Claims;
using System.Collections.Generic;
namespace Oauth.Filter
{
    /// <summary>
    /// Token验证
    /// </summary> 
    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
            return base.ValidateClientAuthentication(context);
        }


        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            context.AdditionalResponseParameters.Add("demo", "自定义输出内容");
            return base.TokenEndpoint(context);
        }


        public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            return Task.Factory.StartNew(() =>
            {
                if (context.UserName == "admin" && context.Password == "000000")
                {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                    identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
                    identity.AddClaim(new Claim(ClaimTypes.UserData, context.Password)); 
                    context.Validated(new AuthenticationTicket(identity, new AuthenticationProperties()));
                }
                else
                { 
                    context.SetError("用户名或者密码错误");
                }
            });
        }
    }
}