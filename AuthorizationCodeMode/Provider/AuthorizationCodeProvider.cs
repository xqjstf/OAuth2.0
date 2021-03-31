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
    public class AuthorizationCodeProvider : IAuthenticationTokenProvider
    {
        private static Dictionary<string, string> codes = new Dictionary<string, string>();

        public void Create(AuthenticationTokenCreateContext context)
        {
            string new_code = Guid.NewGuid().ToString("n");
            context.SetToken(new_code);
            codes.Add(new_code, context.SerializeTicket());
        }

        public Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            Create(context);
            return Task.FromResult<object>(null);
        }

        public void Receive(AuthenticationTokenReceiveContext context)
        {
            string code = context.Token;
            if (codes.ContainsKey(code))
            {
                string value = codes[code];
                codes.Remove(code);
                context.DeserializeTicket(value);
            }
        }

        public Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            Receive(context);
            return Task.FromResult<object>(null);
        }
    }
}