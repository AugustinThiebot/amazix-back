using Amazix.Email;
using Amazix.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<AppUser> _userManager;
    private readonly string _jwtName;
    private readonly string _jwtRefreshName;
    private readonly string _jwtToken;
    private readonly string _jwtIssuer;
    private readonly string _jwtAudience;
    private readonly int _tokenLifetimeMinutes;
    private readonly int _refreshTokenLifetimeHours;
    private readonly IEmailSender _emailSender;

    public AuthController(UserManager<AppUser> userManager, IConfiguration configuration, IEmailSender emailSender)
    {
        _userManager = userManager;
        _jwtName = configuration["Jwt:Name"];
        _jwtRefreshName = configuration["Jwt:RefreshName"];
        _jwtToken = configuration["Jwt:Key"];
        _jwtIssuer = configuration["Jwt:Issuer"];
        _jwtAudience = configuration["Jwt:Audience"];
        _tokenLifetimeMinutes = int.Parse(configuration["Jwt:TokenLifetimeMinutes"]);
        _refreshTokenLifetimeHours = int.Parse(configuration["Jwt:RefreshTokenLifetimeHours"]);
        _emailSender = emailSender;
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

        var message = new Message(new string[] { userDto.Email }, "Welcome", "This is some content");
        _emailSender.SendEmail(message);
        return Ok(new { message = "User registered successfully." });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] UserForLoginDto loginDto)
    {
        AppUser user = await _userManager.FindByEmailAsync(loginDto.Email);
        if (user == null)
        {
            return Unauthorized("Invalid login attempt.");
        }
        else if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            return Unauthorized("Email is not confirmed");
        }
        else if (!await _userManager.CheckPasswordAsync(user, loginDto.Password))
        {
            return Unauthorized("Invalid login attempt.");
        }

        var userToken = this.GenerateJwtToken(user);
        var refreshToken = GenerateRefreshToken();

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.Now.AddHours(_refreshTokenLifetimeHours);
        await _userManager.UpdateAsync(user);

        string token = new JwtSecurityTokenHandler().WriteToken(userToken);

        Response.Cookies.Append(_jwtName, token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = DateTime.Now.AddMinutes(_tokenLifetimeMinutes)
        });
        Response.Cookies.Append(_jwtRefreshName, refreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = DateTime.Now.AddHours(_refreshTokenLifetimeHours),
            Path = "/api/Auth/refresh"
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
        Response.Cookies.Delete(_jwtRefreshName);
        return Ok(new
        {
            message = "Logged out successfully."
        });
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] TokenRequestDto tokenRequest)
    {

        var user = await _userManager.FindByIdAsync(tokenRequest.UserId);
        var refreshToken = Request.Cookies[_jwtRefreshName];
        if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
        {
            return Unauthorized(new { message = "Invalid or expired refresh token."});
        }

        var newJwtToken = GenerateJwtToken(user);
        var newRefreshToken = GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        //user.RefreshTokenExpiryTime = DateTime.Now.AddDays(_refreshTokenLifetimeDays);

        await _userManager.UpdateAsync(user);

        string token = new JwtSecurityTokenHandler().WriteToken(newJwtToken);
        Response.Cookies.Append(_jwtName, token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = DateTime.Now.AddMinutes(_tokenLifetimeMinutes)
        });
        Response.Cookies.Append(_jwtRefreshName, newRefreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = user.RefreshTokenExpiryTime,
            Path = "/api/Auth/refresh"
        });

        return Ok(new { message = "Token refreshed successfully." });
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

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
        }
        return Convert.ToBase64String(randomNumber);
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
