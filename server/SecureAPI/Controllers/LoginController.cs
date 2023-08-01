using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SecureAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class LoginController : ControllerBase
    {        
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login(LoginDto loginDto)
        {
            //Authenticate and Generate jwt
            return new JsonResult(GenerateToken(loginDto));
        }        
        private static string GenerateToken(LoginDto loginDto)
        {
            string secretKey = "H! MaI SeCTeri Key opfg This is the Key. Abo new test Key new this";
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var signingAlgorithm = SecurityAlgorithms.HmacSha256;
            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(GetClaims(loginDto)),
                Expires = DateTime.Now.AddHours(1),
                SigningCredentials = new SigningCredentials(securityKey, signingAlgorithm),
                Issuer = "www.mywebsite.com",
                Audience = "mywebapi",
                NotBefore = DateTime.Now,
                TokenType="JWT"
            };

            var jwtToken = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(jwtToken);
            return tokenString;
        }
        private static IEnumerable<Claim> GetClaims(LoginDto loginDto)
        {
            var claims = new Claim[]
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, loginDto.Email),
                new Claim(ClaimTypes.Role, "Admin")
            };
            return claims;
        }
    }
}
