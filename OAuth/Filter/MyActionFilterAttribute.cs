using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Http.Filters;

namespace OAuth.Filter
{
    public class MyActionFilterAttribute : System.Web.Http.Filters.ActionFilterAttribute
    {
        public override void OnActionExecuted(HttpActionExecutedContext actionExecutedContext)
        {
            //在web.congfig Access-Control-Expose-Headers中对应值即可 以逗号分隔

            ClaimsIdentity oAuthIdentity = new ClaimsIdentity(HttpContext.Current.User.Identity);
            Claim claim = oAuthIdentity.FindFirst(ClaimTypes.UserData);
            actionExecutedContext.ActionContext.Response.Headers.Add("UserData", claim.Value);
        }
    }

}