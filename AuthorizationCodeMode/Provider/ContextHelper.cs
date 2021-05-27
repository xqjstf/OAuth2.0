using AuthorizationCodeMode.Models;
using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Web;

namespace AuthorizationCodeMode.Provider
{
    public static class ContextHelper
    {
        public static void SetCustomError(this OAuthValidateClientAuthenticationContext context, string msg)
        {
            context.Rejected();
            ResponseWrite(context.Response, msg);
        }
        public static void SetCustomError(this AuthenticationTokenReceiveContext context, string msg)
        {
            ResponseWrite(context.Response, msg);
        }

        public static void SetCustomError(this OAuthValidateClientRedirectUriContext context, string msg)
        {
            context.Rejected();
            ResponseWrite(context.Response, msg);
        }
        public static void SetCustomError(this OAuthValidateTokenRequestContext context, string msg)
        {
            context.Rejected();
            ResponseWrite(context.Response, msg);
        }
        public static void SetCustomError(this OAuthValidateAuthorizeRequestContext context, string msg)
        {
            context.Rejected();
            ResponseWrite(context.Response, msg);
        }


        private static readonly MemoryStream bodyStream = new MemoryStream();
        public static void ResponseWrite(IOwinResponse response, string msg)
        {
            response.StatusCode = 200;
            response.ContentType = "application/json";
            response.Write(ResponseMessage.GetJson(1, msg));
            response.Body = bodyStream;
        }
    }
}