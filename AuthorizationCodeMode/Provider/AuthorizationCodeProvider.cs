using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace AuthorizationCodeMode.Provider
{
    /// <summary>
    /// 授权码提供类
    /// </summary>
    public class AuthorizationCodeProvider : AuthenticationTokenProvider
    {
        private static Dictionary<string, string> codes = new Dictionary<string, string>();

        public override Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            return Task.Factory.StartNew(() =>
            {
                string new_code = Guid.NewGuid().ToString("n");
                context.SetToken(new_code);
                codes.Add(new_code, context.SerializeTicket());
            });
        }


        public override Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            return Task.Factory.StartNew(() =>
           {
               string code = context.Token;
               if (codes.ContainsKey(code))
               {
                   string value = codes[code];
                   codes.Remove(code);
                   context.DeserializeTicket(value);
               }
               else
               {
                   context.SetCustomError("code已经失效");
               }
           });
        }
    }
}