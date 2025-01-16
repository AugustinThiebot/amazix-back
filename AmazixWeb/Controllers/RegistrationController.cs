using Amazix.Email;
using Amazix.Email.Interfaces;
using Amazix.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace AmazixWeb.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class RegistrationController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IEmailService _emailService;
        public RegistrationController(UserManager<AppUser> userManager, IEmailService emailService)
        {
            _userManager = userManager;
            _emailService = emailService;
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

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = Url.Action("ConfirmEmail", "Registration", new { userId = user.Id, token = token }, Request.Scheme);
            var messageContent = new StringBuilder()
                .AppendLine("Thank you for signing up for Amazix. To complete your registration, please confirm your email address by clicking the link below :")
                .AppendLine()
                .AppendLine(confirmationLink)
                .AppendLine()
                .AppendLine()
                .AppendLine("If you did not initiate this request or believe it was made in error, do not click on this link. You can safely ignore this email.")
                .AppendLine()
                .AppendLine("Best regards,")
                .AppendLine("The Amazix Team")
                .ToString();
            var message = new Message(new string[] { userDto.Email },
                                    "Welcome to Amazix - Please confirm your email", messageContent);
            _emailService.SendEmail(message);
            return Ok(new { message = "User registered successfully." });
        }



        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                return BadRequest(new { message = "Invalid token or user ID." });
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound(new { message = "User not found." });
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return Ok("Email confirmed successfully");
            }
            return BadRequest(new { message = "Email confirmation failed" });
        }


    }
}
