﻿using Commerce.Models;
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

    public AuthController(UserManager<AppUser> userManager)
    {
        _userManager = userManager;
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
        Response.Cookies.Append("auth_token", token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.Now.AddMinutes(30)
        });
        LoggedUserDto userDto = new LoggedUserDto
        {
            userGuid = user.Id,
            email = user.Email
        };


        return Ok(userDto);
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        Response.Cookies.Delete("auth_token");
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

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("d1-2fGb,8e4M@L?dfqesUu4TOS#32T_@"));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        return new JwtSecurityToken(
            issuer: "localhost:7139",
            audience: "localhost:4200",
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: creds
            );

    }

}
