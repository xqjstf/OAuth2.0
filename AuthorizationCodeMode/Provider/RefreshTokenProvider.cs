using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace AuthorizationCodeMode.Provider
{
    public class RefreshTokenProvider : AuthenticationTokenProvider
    {
        private static Dictionary<string, string> tokens = new Dictionary<string, string>();

        public override void Create(AuthenticationTokenCreateContext context)
        {
            context.Ticket.Properties.IssuedUtc = DateTime.UtcNow;
            context.Ticket.Properties.ExpiresUtc = DateTime.UtcNow.AddDays(60);

            context.SetToken(Guid.NewGuid().ToString("n"));
            tokens.Add(context.Token, context.SerializeTicket());
        }

        public override void Receive(AuthenticationTokenReceiveContext context)
        {
            string token = context.Token;
            if (tokens.ContainsKey(token))
            {
                string value = tokens[token];
                tokens.Remove(token);
                context.DeserializeTicket(value);
            }
        }
    }
}