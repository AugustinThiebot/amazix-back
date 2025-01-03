using Commerce.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<AppUser> _userManager;
    private readonly string _jwtName;
    private readonly string _jwtToken;
    private readonly string _jwtIssuer;
    private readonly string _jwtAudience;
    private readonly int _tokenLifetimeMinutes;

    public AuthController(UserManager<AppUser> userManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _jwtName = configuration["Jwt:Name"];
        _jwtToken = configuration["Jwt:Key"];
        _jwtIssuer = configuration["Jwt:Issuer"];
        _jwtAudience = configuration["Jwt:Audience"];
        _tokenLifetimeMinutes = int.Parse(configuration["Jwt:TokenLifetimeMinutes"]);
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] UserForRegistrationDto userDto)
    {
        var user = new AppUser
        {
            UserName = userDto.Email,
            Email = userDto.Email,
        };

        var result = await _userManager.CreateAsync(user, userDto.Password);

        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        return Ok(new { message = "User registered successfully." });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] UserForLoginDto loginDto)
    {
        var user = await _userManager.FindByEmailAsync(loginDto.Email);
        if (user == null || !await _userManager.CheckPasswordAsync(user, loginDto.Password))
        {
            return Unauthorized("Invalid login attempt.");
        }



        var userToken = this.GenerateJwtToken(user);
        string token = new JwtSecurityTokenHandler().WriteToken(userToken);
        Response.Cookies.Append(_jwtName, token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = DateTime.Now.AddMinutes(_tokenLifetimeMinutes)
        });
        LoggedUserDto userDto = new LoggedUserDto
        {
            userGuid = user.Id,
            email = user.Email
        };


        return Ok(userDto);
    }

    
    [HttpPost("logout")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public IActionResult Logout()
    {
        Response.Cookies.Delete(_jwtName);
        return Ok(new
        {
            message = "Logged out successfully."
        });
    }


    private JwtSecurityToken GenerateJwtToken(AppUser user)
    {
        // Génération du JWT
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.Email, user.Email)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtToken));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        return new JwtSecurityToken(
            issuer: _jwtIssuer,
            audience: _jwtAudience,
            claims: claims,
            expires: DateTime.Now.AddMinutes(_tokenLifetimeMinutes),
            signingCredentials: creds
            );

    }



    [HttpGet("validate-token")]
    public IActionResult ValidateToken()
    {
        var token = Request.Cookies[_jwtName];
        if (string.IsNullOrEmpty(token))
        {
            return Unauthorized(new { message = "Token is missing or invalid." });
        }

        try
        {
            var handler = new JwtSecurityTokenHandler();
            var tokenValidationParams = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _jwtIssuer,
                ValidAudience = _jwtAudience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtToken))
            };

            handler.ValidateToken(token, tokenValidationParams, out _);
            return Ok(new { valid = true });
        }
        catch
        {
            return Unauthorized(new { valid = false });
        }
    }


}
