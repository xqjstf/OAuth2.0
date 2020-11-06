using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json.Serialization;
using OAuth.Filter;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Formatting;
using System.Web.Http;
using System.Web.Http.Cors;

namespace OAuth
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {

            //跨域处理
            var cors = new EnableCorsAttribute(AuthorizationServerProvider.AllowOriginDomain, "*", "*");
            config.EnableCors(cors);



            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{action}"
            );
        }
    }
}
