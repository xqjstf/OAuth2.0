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
    /// <summary>
    /// Code返回处理
    /// </summary>
    public class AuthorizationServerProvider : OAuthAuthorizationServerProvider
    { 
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
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
                    context.SetCustomError("请求类型有误");
                }
            });
        }

        #region 获取Code
        /// <summary>
        /// 第一步
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            return Task.Factory.StartNew(() =>
            {
                if (string.IsNullOrEmpty(context.RedirectUri))
                {
                    context.SetCustomError("地址不能为空");
                }
                else
                {
                    context.Validated();
                }
            });
        }

        /// <summary>
        /// 第二步
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task ValidateAuthorizeRequest(OAuthValidateAuthorizeRequestContext context)
        {
            //获取code的时候会调用
            return Task.Factory.StartNew(() =>
            {
                if (string.IsNullOrEmpty(context.ClientContext.ClientId))
                {
                    context.SetCustomError("client_id不能为空");
                }
                else if (context.ClientContext.ClientId.StartsWith("AAA") == false)
                {
                    context.SetCustomError("客户端未授权");
                }
                else
                {
                    context.Validated();
                }
            });
        }

        /// <summary>
        /// 第二步验证失败执行
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            return Task.Factory.StartNew(() =>
            {
                if (context.HasError)
                {
                    context.SetCustomError(context.Error);
                }
                else if (context.TryGetFormCredentials(out string clientId, out string clientSecret))
                {
                    context.Validated();
                }
                else
                {
                    context.SetCustomError("客户端相关参数有误");
                }
            });
        }

        /// <summary>
        /// 第四步：完成认证，跳转到重定向URI
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override async Task AuthorizeEndpoint(OAuthAuthorizeEndpointContext context)
        { 
            var redirectUri = context.AuthorizeRequest.RedirectUri;
            var clientId = context.AuthorizeRequest.ClientId;
            var identity = new ClaimsIdentity(new GenericIdentity(clientId, OAuthDefaults.AuthenticationType));

            var authorizeCodeContext = new AuthenticationTokenCreateContext(
                context.OwinContext,
                context.Options.AuthorizationCodeFormat,
                new AuthenticationTicket(identity,
                    new AuthenticationProperties(new Dictionary<string, string>
                    {
                        {"client_id", clientId},
                        {"redirect_uri", redirectUri}
                    })
                    {
                        IssuedUtc = DateTimeOffset.UtcNow,
                        ExpiresUtc = DateTimeOffset.UtcNow.Add(context.Options.AuthorizationCodeExpireTimeSpan)
                    })
                );  

            await context.Options.AuthorizationCodeProvider.CreateAsync(authorizeCodeContext);

            //为了测试方便，直接打印出code
            context.Response.Write(Uri.EscapeDataString(authorizeCodeContext.Token));

            //正常使用时是把code加在重定向网址后面
            //context.Response.Redirect(redirectUri + "?code=" + Uri.EscapeDataString(authorizeCodeContext.Token)); 
            context.RequestCompleted();
        }
        #endregion
    }
}