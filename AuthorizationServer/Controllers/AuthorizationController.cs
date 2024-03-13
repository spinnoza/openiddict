using System.Collections.Immutable;
using System.Security.Claims;
using System.Web;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthorizationServer.Controllers
{
    [ApiController]
    public class AuthorizationController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly AuthService _authService;


        public AuthorizationController(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager,
            IOpenIddictScopeManager scopeManager,
            AuthService authService)
        {
            _applicationManager = applicationManager;
            _authorizationManager = authorizationManager;
            _scopeManager = scopeManager;
            _authService = authService;
        }

        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
      //  [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            // Try to retrieve the user principal stored in the authentication cookie and redirect
            // the user agent to the login page (or to an external provider) in the following cases:
            // 在以下情况下，尝试检索存储在身份验证cookie中的用户主体，并将用户代理重定向到登录页面(或外部提供者):

            //

            //  - If the user principal can't be extracted or the cookie is too old.
            //如果无法提取用户主体或cookie太旧。
            //  - If prompt=login was specified by the client application.
            // 如果客户端应用程序指定了prompt=login。
            //  - If a max_age parameter was provided and the authentication cookie is not considered "fresh" enough.
            // 如果提供了max_age参数，并且认为身份验证cookie不够“新鲜”。


            // For scenarios where the default authentication handler configured in the ASP.NET Core
            // authentication options shouldn't be used, a specific scheme can be specified here.

            //对于在asp.net中配置默认身份验证处理程序的场景。. NET核心身份验证选项不应该使用，可以在这里指定一个特定的方案。
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            var isAuthenticated  = _authService.IsAuthenticated(result, request);

            var parameters = _authService.ParseOAuthParameters(HttpContext);

            if (!isAuthenticated)
            {
                //// If the client application requested promptless authentication,
                //// return an error indicating that the user is not logged in.
                //if (request.HasPrompt(Prompts.None))
                //{
                //    return Forbid(
                //        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                //        properties: new AuthenticationProperties(new Dictionary<string, string>
                //        {
                //            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                //            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                //        }));
                //}

                // To avoid endless login -> authorization redirects, the prompt=login flag
                // is removed from the authorization request payload before redirecting the user.
                //var prompt = string.Join(" ", request.GetPrompts().Remove(Prompts.Login));

               

                //parameters.Add(KeyValuePair.Create(Parameters.Prompt, new StringValues(prompt)));

                // For scenarios where the default challenge handler configured in the ASP.NET Core
                // authentication options shouldn't be used, a specific scheme can be specified here.
                return Challenge(
                    authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties
                    {
                        RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request,parameters)
                    }
                );
            }

            // Retrieve the profile of the logged in user.
            //var user = await _userManager.GetUserAsync(result.Principal) ??
            //    throw new InvalidOperationException("The user details cannot be retrieved.");

            // Retrieve the application details from the database.
            // 从数据库中检索应用程序详细信息。
            var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
                throw new InvalidOperationException("Details concerning the calling client application cannot be found.");


            #region 废弃代码
            // Retrieve the permanent authorizations associated with the user and the calling client application.
            // 检索与用户和调用客户端应用程序相关联的永久授权。
            //var authorizations = await _authorizationManager.FindAsync(
            //    //subject: await _userManager.GetUserIdAsync(user),
            //    subject:Consts.Email,
            //    client: await _applicationManager.GetIdAsync(application),
            //    status: Statuses.Valid,
            //    type: AuthorizationTypes.Permanent,
            //    scopes: request.GetScopes()).ToListAsync();

            //switch (await _applicationManager.GetConsentTypeAsync(application))
            //{
            //    // If the consent is external (e.g when authorizations are granted by a sysadmin),
            //    // immediately return an error if no authorization can be found in the database.
            //    case ConsentTypes.External when authorizations.Count is 0:
            //        return Forbid(
            //            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            //            properties: new AuthenticationProperties(new Dictionary<string, string>
            //            {
            //                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
            //                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
            //                    "The logged in user is not allowed to access this client application."
            //            }));

            //    // If the consent is implicit or if an authorization was found,
            //    // return an authorization response without displaying the consent form.
            //    case ConsentTypes.Implicit:
            //    case ConsentTypes.External when authorizations.Count is not 0:
            //    case ConsentTypes.Explicit when authorizations.Count is not 0 && !request.HasPrompt(Prompts.Consent):
            //        // Create the claims-based identity that will be used by OpenIddict to generate tokens.
            //        var identity = new ClaimsIdentity(
            //            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            //            nameType: Claims.Name,
            //            roleType: Claims.Role);

            //        // Add the claims that will be persisted in the tokens.
            //        identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
            //                .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
            //                .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
            //                .SetClaim(Claims.PreferredUsername, await _userManager.GetUserNameAsync(user))
            //                .SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());

            //        // Note: in this sample, the granted scopes match the requested scope
            //        // but you may want to allow the user to uncheck specific scopes.
            //        // For that, simply restrict the list of scopes before calling SetScopes.
            //        identity.SetScopes(request.GetScopes());
            //        identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

            //        // Automatically create a permanent authorization to avoid requiring explicit consent
            //        // for future authorization or token requests containing the same scopes.
            //        var authorization = authorizations.LastOrDefault();
            //        authorization ??= await _authorizationManager.CreateAsync(
            //            identity: identity,
            //            subject: await _userManager.GetUserIdAsync(user),
            //            client: await _applicationManager.GetIdAsync(application),
            //            type: AuthorizationTypes.Permanent,
            //            scopes: identity.GetScopes());

            //        identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
            //        identity.SetDestinations(GetDestinations);

            //        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            //    // At this point, no authorization was found in the database and an error must be returned
            //    // if the client application specified prompt=none in the authorization request.
            //    case ConsentTypes.Explicit when request.HasPrompt(Prompts.None):
            //    case ConsentTypes.Systematic when request.HasPrompt(Prompts.None):
            //        return Forbid(
            //            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            //            properties: new AuthenticationProperties(new Dictionary<string, string>
            //            {
            //                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
            //                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
            //                    "Interactive user consent is required."
            //            }));

            //    // In every other case, render the consent form.
            //    default:
            //        return View(new AuthorizeViewModel
            //        {
            //            ApplicationName = await _applicationManager.GetLocalizedDisplayNameAsync(application),
            //            Scope = request.Scope
            //        });
            //}


            #endregion

            var consentClaim = result.Principal?.GetClaim(Consts.ConsentNaming);
            if (consentClaim != Consts.ConsentNaming)
            {
                var returnUrl = HttpUtility.UrlEncode(_authService.BuildRedirectUrl(HttpContext.Request, parameters));
                var consentRedirectUrl = $"/Consent?returnUrl={returnUrl}";

                return Redirect(consentRedirectUrl);
            }

            var userId = result.Principal.FindFirst(ClaimTypes.Email)!.Value;

            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, userId)
                .SetClaim(Claims.Email, userId)
                .SetClaim(Claims.Name, userId)
                .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

            identity.SetScopes(request.GetScopes());
            identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

            //identity.SetDestinations(c => AuthorizationService.GetDestinations(identity, c));

            //return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var authorizations = await _authorizationManager.FindAsync(
                subject: userId,
                client: await _applicationManager.GetIdAsync(application),
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: request.GetScopes()
            ).ToListAsync();

            var authorization = authorizations.LastOrDefault();

            authorization ??=  _authorizationManager.CreateAsync(
                identity: identity,
                subject: userId,
                client: await _applicationManager.GetIdAsync(application),
                type: AuthorizationTypes.Permanent,
                scopes: identity.GetScopes()
            );

            identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
            identity.SetDestinations(AuthService.GetDestinations);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);


        }


        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
                throw new InvalidOperationException("The specified grant type is not supported.");

            var result =
                await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var userId = result.Principal?.GetClaim(Claims.Subject);

            if (string.IsNullOrEmpty(userId))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Cannot find user from the token."
                    }));
            }

            var identity = new ClaimsIdentity(result.Principal.Claims,
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, userId)
                .SetClaim(Claims.Email, userId)
                .SetClaim(Claims.Name, userId)
                .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

            identity.SetDestinations(AuthService.GetDestinations);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }


        [HttpGet("~/connect/logout")]
        [HttpPost("~/connect/logout")]
        public async Task<IActionResult> LogoutPost()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = "/"
                });
        }


        private static IEnumerable<string> GetDestinations(Claim claim)
      {
          // Note: by default, claims are NOT automatically included in the access and identity tokens.
          // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
          // whether they should be included in access tokens, in identity tokens or in both.

          switch (claim.Type)
          {
              case Claims.Name or Claims.PreferredUsername:
                  yield return Destinations.AccessToken;

                  if (claim.Subject.HasScope(Scopes.Profile))
                      yield return Destinations.IdentityToken;

                  yield break;

              case Claims.Email:
                  yield return Destinations.AccessToken;

                  if (claim.Subject.HasScope(Scopes.Email))
                      yield return Destinations.IdentityToken;

                  yield break;

              case Claims.Role:
                  yield return Destinations.AccessToken;

                  if (claim.Subject.HasScope(Scopes.Roles))
                      yield return Destinations.IdentityToken;

                  yield break;

              // Never include the security stamp in the access and identity tokens, as it's a secret value.
              case "AspNet.Identity.SecurityStamp": yield break;

              default:
                  yield return Destinations.AccessToken;
                  yield break;
          }
      }
    }
}
