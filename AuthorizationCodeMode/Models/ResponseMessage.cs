using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AuthorizationCodeMode.Models
{
    public class ResponseMessage
    {
        public int errcode { get; set; }
        public string errmsg { get; set; }


        public static ResponseMessage GetModel(int code, string msg)
        {
            return new ResponseMessage() { errcode = code, errmsg = msg };
        }
        public static string GetJson(int code, string msg)
        {
            return JsonConvert.SerializeObject(new ResponseMessage() { errcode = code, errmsg = msg });
        }
    }
}