﻿using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;

namespace OAuth.Filter
{
    public class RefreshTokenProvider : AuthenticationTokenProvider
    {
        public static Dictionary<string, string> dicTOken = new Dictionary<string, string>();

        /// <summary>
        /// 生成RefreshToken值
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            return Task.Factory.StartNew(() =>
            {
                var refreshTokenId = Guid.NewGuid().ToString("n");
                context.Ticket.Properties.IssuedUtc = DateTime.UtcNow;
                context.Ticket.Properties.ExpiresUtc = DateTime.UtcNow.AddMinutes(AuthorizationServerProvider.AccessTokenExpireTimeSpan * 2);//RefreshToken 过期时间
                context.SetToken(refreshTokenId);

                //添加到内存中
                dicTOken.Add(refreshTokenId, context.SerializeTicket());
            });
        }

        /// <summary>
        /// 由 refresh_token 解析成 access_token
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {

            return Task.Factory.StartNew(() =>
           {
               string reqOrigin = context.Request.Headers.Get("Origin");
               if (AuthorizationServerProvider.AllowOriginDomain == "*" || Array.IndexOf(AuthorizationServerProvider.AllowOriginDomain.Split(','), reqOrigin) > -1)
               {
                   context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new string[] { reqOrigin });
               }
               if (dicTOken.ContainsKey(context.Token))
               {
                   context.DeserializeTicket(dicTOken[context.Token]);
                   dicTOken.Remove(context.Token);
               }
           });
        }
    }
}