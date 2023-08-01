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
    [AllowAnonymous]
    [ApiController]
    [Route("[controller]")]
    public class LoginController : ControllerBase
    {        
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login(UserDto userDto)
        {
            //Authenticate and Generate jwt
            return new JsonResult(GenerateToken(userDto));
        }        
        private static string GenerateToken(UserDto userDto)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Common.SecretKey));
            var signingAlgorithm = SecurityAlgorithms.HmacSha256;
            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(GetClaims(userDto)),
                Expires = DateTime.Now.AddHours(1),
                SigningCredentials = new SigningCredentials(securityKey, signingAlgorithm),
                Issuer = Common.Issuer,
                Audience = Common.Audience,
                NotBefore = DateTime.Now,
                TokenType = Common.TokenType
            };

            var jwtToken = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(jwtToken);
            return tokenString;
        }
        private static IEnumerable<Claim> GetClaims(UserDto userDto)
        {
            var claims = new Claim[]
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, userDto.Email),
                new Claim(ClaimTypes.Role, "Admin")
            };
            return claims;
        }
    }
}
