using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace AuthorizationServer.Pages
{
    [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    public class ConsentModel : PageModel
    {
        [BindProperty]
        public string ReturnUrl { get; set; }

        public IActionResult OnGet(string returnUrl)
        {
            ReturnUrl = returnUrl;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string grant)
        {

            if (grant!= Consts.GrantAccessValue)
            {
                return Forbid();
            }

            var consentCliaim = User.GetClaim(Consts.ConsentNaming);

            if (consentCliaim.IsNullOrEmpty())
            {
                User.SetClaim(Consts.ConsentNaming, grant);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, User);

            }

            //User.SetClaim(Consts.ConsentNaming, grant);

            //await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, User);
            return Redirect(ReturnUrl);
        }
    }
}
