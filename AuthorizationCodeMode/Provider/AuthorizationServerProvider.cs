using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Web;

namespace AuthorizationCodeMode.Provider
{
    public class AuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            return Task.Factory.StartNew(() =>
            {
                if (string.IsNullOrEmpty(context.RedirectUri))
                {
                    context.Rejected();
                    context.SetCustomError(1, "地址不能为空");
                }
                else
                {
                    context.Validated();
                }
            });
        }


        public override Task ValidateAuthorizeRequest(OAuthValidateAuthorizeRequestContext context)
        {
            return Task.Factory.StartNew(() =>
            {
                if (context.AuthorizeRequest.ClientId.StartsWith("AAA"))
                {
                    context.Validated();
                }
                else
                {
                    context.Rejected();
                    context.SetCustomError(1, "无效请求");
                }
            });
        }

        public override async Task AuthorizeEndpoint(OAuthAuthorizeEndpointContext context)
        {
            var redirectUri = context.Request.Query["redirect_uri"];
            var clientId = context.Request.Query["client_id"];
            var identity = new ClaimsIdentity(new GenericIdentity(
                clientId, OAuthDefaults.AuthenticationType));

            var authorizeCodeContext = new AuthenticationTokenCreateContext(
                context.OwinContext,
                context.Options.AuthorizationCodeFormat,
                new AuthenticationTicket(
                    identity,
                    new AuthenticationProperties(new Dictionary<string, string>
                    { {"client_id", clientId}, {"redirect_uri", redirectUri}  })
                    {
                        IssuedUtc = DateTimeOffset.UtcNow,
                        ExpiresUtc = DateTimeOffset.UtcNow.Add(context.Options.AuthorizationCodeExpireTimeSpan)
                    }));

            await context.Options.AuthorizationCodeProvider.CreateAsync(authorizeCodeContext);

            context.Response.Write(Uri.EscapeDataString(authorizeCodeContext.Token));//为了测试方便，直接打印出code
                                                                                     //context.Response.Redirect(redirectUri + "?code=" + Uri.EscapeDataString(authorizeCodeContext.Token));//正常使用时是把code加在重定向网址后面

            context.RequestCompleted();

        }


        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            return Task.Factory.StartNew(() =>
            {
                context.TryGetFormCredentials(out string clientId, out string clientSecret);
                if (clientId.StartsWith("AAA"))
                {
                    context.Validated();
                }
                else
                {
                    context.Rejected();
                    context.SetCustomError(0, "未授权的客户端");
                }
            });
        }

        public override Task ValidateTokenRequest(OAuthValidateTokenRequestContext context)
        {
            return Task.Factory.StartNew(() =>
            {
                if (context.TokenRequest.IsAuthorizationCodeGrantType)
                {
                    context.Validated();
                }
                else if (context.TokenRequest.IsRefreshTokenGrantType)
                {
                    context.Validated();
                }
                else
                {
                    context.Rejected();
                    context.SetCustomError(1, "无效密钥获取请求");
                }
            });
        }
    }
}