using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace AuthorizationCodeMode.Controllers
{
    [Authorize]
    public class HomeController : ApiController
    {
        public string Get()
        {
            return "登录人：" + HttpContext.Current.User.Identity.Name;
        }

        [HttpDelete]
        [AllowAnonymous]
        public string Delete()
        {
            return "删除成功";
        }
    }
}
