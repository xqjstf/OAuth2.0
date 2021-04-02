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
                    context.SetCustomError(1, "地址不能为空");
                }
                else
                {
                    context.Validated();
                }
            });
        }



        /// <summary>
        /// 完成认证，跳转到重定向URI
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
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
                    context.SetCustomError(1, "请求有误");
                }
            });
        }
        public override Task ValidateAuthorizeRequest(OAuthValidateAuthorizeRequestContext context)
        {
            //获取code的时候会调用
            return Task.Factory.StartNew(() =>
            {
                if (string.IsNullOrEmpty(context.ClientContext.ClientId))
                {
                    context.SetCustomError(0, "客户端编号参数不能为空");
                }
                else if (context.ClientContext.ClientId.StartsWith("AAA") == false)
                {
                    context.SetCustomError(0, "客户端未被授权");
                }
                else
                {
                    context.Validated();
                }
            });
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            //ValidateAuthorizeRequest 验证失败会调用
            return Task.Factory.StartNew(() =>
            {
                if (context.TryGetFormCredentials(out string clientId, out string clientSecret))
                {
                    if (clientId.StartsWith("AAA") == false)
                    {
                        context.SetCustomError(0, "客户端未授权");
                    }
                    else
                    {
                        context.Validated();
                    }
                }
                else
                {
                    context.SetCustomError(1, "客户端相关参数有误");
                    return;
                }
            });
        }
    }
}