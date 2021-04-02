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
        public static void SetCustomError(this OAuthValidateClientAuthenticationContext context, int code, string msg)
        {
            ResponseWrite(context.Response, ResponseMessage.GetJson(code, msg));

        }
        public static void SetCustomError(this AuthenticationTokenReceiveContext context, int code, string msg)
        {
            ResponseWrite(context.Response, ResponseMessage.GetJson(code, msg));
        }

        public static void SetCustomError(this OAuthValidateClientRedirectUriContext context, int code, string msg)
        {
            ResponseWrite(context.Response, ResponseMessage.GetJson(code, msg));
        }
        public static void SetCustomError(this OAuthValidateTokenRequestContext context, int code, string msg)
        {
            ResponseWrite(context.Response, ResponseMessage.GetJson(code, msg));
        }
        public static void SetCustomError(this OAuthValidateAuthorizeRequestContext context, int code, string msg)
        {
            ResponseWrite(context.Response, ResponseMessage.GetJson(code, msg));
        }


        private static readonly MemoryStream bodyStream = new MemoryStream();
        public static void ResponseWrite(IOwinResponse response, string json)
        {
            response.StatusCode = 200;
            response.ContentType = "application/json";
            response.Write(json);
            response.Body = bodyStream;
        }
    }
}