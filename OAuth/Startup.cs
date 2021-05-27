using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth; 
using OAuth.Filter;
using Owin;
using System;
using System.Web.Http;

[assembly: OwinStartup(typeof(OAuth.Startup))]
namespace OAuth
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var config = new HttpConfiguration();
            WebApiConfig.Register(config);
            ConfigureOAuth(app);
            app.UseWebApi(config);  //这一行代码必须放在ConfiureOAuth(app)之后 
        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"), //获取 access_token 授权服务请求地址
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(AuthorizationServerProvider.AccessTokenExpireTimeSpan), //access_token 过期时间 
                Provider = new AuthorizationServerProvider(),//access_token 相关授权服务 
                RefreshTokenProvider = new RefreshTokenProvider(),//refresh_token 授权服务， 
            };
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
        }
    }
}
