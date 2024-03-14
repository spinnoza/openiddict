using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace ResourceServer.Controllers
{
    [ApiController]
    [Route("resources")]
    public class ResourceController : Controller
    {
        [Authorize]
        [HttpGet]
        public async Task<IActionResult> GetSecretResources()
        {
            var user = HttpContext.User?.Identity?.Name;
            return Ok($"user: {user}");

            //var claim = User.Claims.FirstOrDefault(e=>e Claims.Subject));


        }
    }
}
