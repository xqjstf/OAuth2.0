using OAuth.Filter;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http; 

namespace OAuth.Controllers
{
    [Authorize]
    public class HomeController : ApiController
    { 
        [MyActionFilter]
        [HttpGet]
        public string getList()
        {
            ClaimsIdentity oAuthIdentity = new ClaimsIdentity(HttpContext.Current.User.Identity); 
            Claim claim = oAuthIdentity.FindFirst(ClaimTypes.UserData); 
            return "UserData：" + claim.Value;
        }

        [AllowAnonymous]
        [HttpGet]
        public string get2()
        {
            return "测试";
        }
    }
}
