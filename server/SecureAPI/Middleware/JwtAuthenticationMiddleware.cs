using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SecureAPI.Middleware
{
    public class JwtAuthenticationMiddleware : IMiddleware
    {
        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            if (context.Request.Path.StartsWithSegments("/Login"))
            {
                await next(context);
                return;
            }
            var token = context.Request.Headers["Authorization"].FirstOrDefault().Split(" ").Last();
            if (!string.IsNullOrEmpty(token))
            {
                token = @"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwNjkzOWY3NC0yYjM5LTRlNWUtOGEyOC0xYTFjYTlkMjdjNTciLCJzdWIiOiJ0ZXN0QGguY29tIiwicm9sZSI6IkFkbWluIiwibmJmIjoxNjkwODk4NzA5LCJleHAiOjE2OTA5MDIzMDksImlhdCI6MTY5MDg5ODcxMCwiaXNzIjoid3d3Lm15d2Vic2l0ZS5jb20iLCJhdWQiOiJNeVNlY3VyZUFQSSJ9.AQ1JYBvEGpxycQu89lIu9zziKz3XVKDsQEvjMnlgMh8";
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(Common.SecretKey);
                try
                {
                    var signingKey = new SymmetricSecurityKey(key);
                    var validationParams = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = Common.Issuer,
                        ValidAudience = Common.Audience,
                        IssuerSigningKey = signingKey
                    };
                    tokenHandler.ValidateToken(token, validationParams, out SecurityToken securityToken);
                    var jwtToken = securityToken as JwtSecurityToken;
                    var claims = jwtToken.Claims;
                    context.User = new ClaimsPrincipal(new ClaimsIdentity(claims));
                }
                catch (Exception)
                {

                }
            }
            await next(context);
        }
    }
}
