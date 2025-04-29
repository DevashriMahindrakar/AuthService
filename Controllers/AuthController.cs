using AuthService.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly JwtSettings _jwtSettings;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IOptions<JwtSettings> jwtOptions, ILogger<AuthController> logger)
    {
        _jwtSettings = jwtOptions.Value;
        _logger = logger;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        if (request.Username == "user" && request.Password == "password")
        {
            var claims = new[]
            {
                    new Claim(ClaimTypes.Name, request.Username),
                    new Claim(ClaimTypes.Role, "User")
                };

            if (string.IsNullOrEmpty(_jwtSettings.SecretKey) || _jwtSettings.SecretKey.Length < 32)
            {
                throw new InvalidOperationException("JWT Secret Key is not properly configured.");
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpiryMinutes),
            signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return Ok(new { token = jwt });
        }

        _logger.LogWarning("Invalid login attempt for user: {Username}", request.Username);
        return Unauthorized(new ErrorResponse
        {
            Message = "Unauthorized",
            Details = "Invalid username or password."
        });

    }
}