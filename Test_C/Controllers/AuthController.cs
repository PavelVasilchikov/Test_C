using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Test_C.Models;
using Test_C.Services;
using static Test_C.Models.DTOs;

namespace Test_C.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserService _users;

        public AuthController(UserService users)
        {
            _users = users;
        }

        [HttpPost("login")]
        public IActionResult Login([FromQuery] LoginDto dto)
        {
            var user = _users.GetUsers().FirstOrDefault(u => u.Login == dto.Username && u.Password == dto.Password && !u.RevokedOn.HasValue);

            if (user == null)
                return Unauthorized("Неверные учетные данные");

            var token = GenerateJwtToken(user.Login, user.Admin);
            return Ok(new { Token = token });
        }

        private string GenerateJwtToken(string username, bool isAdmin)
        {
            var secretKey = "super-secret-key-that-is-longer-than-32-characters";
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, isAdmin ? "Admin" : "User")
            };

            var token = new JwtSecurityToken(
                issuer: "self",
                audience: "users",
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}