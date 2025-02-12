﻿using System;

using AppService.Acmebot.Internal;

using Azure.WebJobs.Extensions.HttpApi;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

namespace AppService.Acmebot.Functions
{
    public class StaticPage : HttpFunctionBase
    {
        public StaticPage(IHttpContextAccessor httpContextAccessor)
            : base(httpContextAccessor)
        {
        }

        [FunctionName(nameof(StaticPage) + "_" + nameof(AddCertificate))]
        public IActionResult AddCertificate(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "static-page/add-certificate")] HttpRequest req,
            ILogger log)
        {
            if (!IsEasyAuthEnabled || !User.IsAppAuthorized())
            {
                return Forbid();
            }

            return File("static/add-certificate.html");
        }

        private static bool IsEasyAuthEnabled => bool.TryParse(Environment.GetEnvironmentVariable("WEBSITE_AUTH_ENABLED"), out var result) && result;
    }
}
