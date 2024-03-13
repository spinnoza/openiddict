using IdentityModel;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthorizationServer.Controllers
{
    public class TokenController : Controller
    {
        //private readonly IHostingEnvironment _env;

        //public TokenController(IHostingEnvironment env)
        //{
        //    _env = env;
        //}

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult GetToken([FromBody] LoginModel model)
        {
            if (model.UserName != "admin" || model.Password != "123456")
            {
                return Json(new { Error = "用户名或密码错误" });
            }

            User user = new User
            {
                Id = 1,
                Name = model.UserName,
                Email = "admin@xcode.me",
                Birthday = DateTime.Now.AddYears(-10),
                Password = model.Password,
                PhoneNumber = "18888888888"
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(Consts.Secret);

           // string keyPrivate = System.IO.File.ReadAllText(Path.Combine(_env.ContentRootPath, "key.private.json"));

            //var keyParameters = JsonConvert.DeserializeObject<RSAParameters>(keyPrivate);

            //var rsaSecurityKey = new RsaSecurityKey(keyParameters);

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new Claim[] {
                    new Claim(JwtClaimTypes.Audience,"aspnetcoreweb"),
                    new Claim(JwtClaimTypes.Issuer,"www.xcode.me"),
                    new Claim(JwtClaimTypes.Id, user.Id.ToString()),
                    new Claim(JwtClaimTypes.Name, user.Name),
                    new Claim(JwtClaimTypes.Email, user.Email),
                    new Claim(JwtClaimTypes.PhoneNumber, user.PhoneNumber),
                    new Claim(JwtClaimTypes.Role, "manager")
                }),
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                // SigningCredentials = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            string tokenString = tokenHandler.WriteToken(token);

            return Json(new { Token = tokenString });
        }
    }
}
