using Microsoft.Owin.Security.OAuth;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using System.Security.Claims;
using System.Collections.Generic;
using System;

namespace OAuth.Filter
{
    /// <summary>
    /// Token验证
    /// </summary> 
    public class AuthorizationServerProvider : OAuthAuthorizationServerProvider
    {

        /// <summary>
        /// token过期时间(分钟)
        /// </summary>
        public static int AccessTokenExpireTimeSpan
        {
            get
            {
                return Convert.ToInt32(System.Configuration.ConfigurationManager.AppSettings["AccessTokenExpireTimeSpan"]);
            }
        }

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

        /// <summary>
        /// 刷新是调用
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        { 
            return Task.Factory.StartNew(() =>
            {
                context.Ticket.Identity.TryRemoveClaim(context.Ticket.Identity.FindFirst(ClaimTypes.UserData));
                context.Ticket.Identity.AddClaim(new Claim(ClaimTypes.UserData, "New UserData"));
                base.OnGrantRefreshToken(context);
            });
        }
    }
}