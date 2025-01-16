using Amazix.Models;
using AmazixWeb.Services.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace AmazixWeb.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class RegistrationController : ControllerBase
    {
        private readonly IRegistrationService _registrationService;
        public RegistrationController(IRegistrationService registrationService)
        {
            _registrationService = registrationService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserForRegistrationDto userDto)
        {
            var result = await _registrationService.RegisterUserAsync(userDto);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }
            return Ok(new { message = "User registered successfully." });
        }



        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            try
            {
                var result = await _registrationService.ConfirmEmailAsync(userId, token);
                if (result.Succeeded)
                {
                    return Ok("Email confirmed successfully.");
                }
                return BadRequest(new { message = "Email confirmation failed." });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.ToString());
            }
        }
    }
}
