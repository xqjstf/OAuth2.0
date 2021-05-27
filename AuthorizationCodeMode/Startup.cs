using AuthorizationCodeMode.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json.Serialization;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Formatting;
using System.Web;
using System.Web.Http;


[assembly: OwinStartup(typeof(AuthorizationCodeMode.Startup))]//让整个网站的入口为Startup这个类
namespace AuthorizationCodeMode
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            //配置OAuth
            ConfigureOAuth(app);

            //配置网站路由等信息
            HttpConfiguration config = new HttpConfiguration();
            WebApiConfig.Register(config);


            //允许跨域访问
            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);

            app.UseWebApi(config);
        }

        private void ConfigureOAuth(IAppBuilder app)
        {
            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,//允许http而非https访问
                AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Active,//**授权码模式
                TokenEndpointPath = new PathString("/token"),//访问host/token获取AccessToken
                AuthorizeEndpointPath = new PathString("/auth"),//访问host/auth获取授权码
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(30),//AccessToken在30分钟后过期
                Provider = new AuthorizationServerProvider(),//AccessToken的提供类
                AuthorizationCodeProvider = new AuthorizationCodeProvider(),//授权码的提供类      
                RefreshTokenProvider = new RefreshTokenProvider(),//RefreshToken的提供类   
                ApplicationCanDisplayErrors = true
            };

            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
        }
    }
}