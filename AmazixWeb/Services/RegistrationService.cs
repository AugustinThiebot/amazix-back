using Amazix.Email;
using Amazix.Models;
using AmazixWeb.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Amazix.Email.Interfaces;

namespace AmazixWeb.Services
{
    public class RegistrationService: IRegistrationService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IEmailService _emailService;
        private readonly IUrlHelper _urlHelper;
        private readonly HttpRequest _request;
        public RegistrationService(UserManager<AppUser> userManager, IEmailService emailService, IUrlHelper urlHelper, IHttpContextAccessor httpContextAccessor) {
            _userManager = userManager;
            _emailService = emailService;
            _urlHelper = urlHelper;
            _request = httpContextAccessor.HttpContext.Request;
        }

        public async Task<IdentityResult> RegisterUserAsync(UserForRegistrationDto userDto)
        {
            var user = new AppUser
            {
                UserName = userDto.Email,
                Email = userDto.Email,
            };

            var result = await _userManager.CreateAsync(user, userDto.Password);

            if (result.Succeeded) {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = _urlHelper.Action("ConfirmEmail", "Registration", new { userId = user.Id, token = token }, _request.Scheme);
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
            }
            return result;
        }

        public async Task<IdentityResult> ConfirmEmailAsync(string userId, string token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                throw new ArgumentException("Invalid token or user ID.");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new ArgumentException("User not found.");
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            return result;
        }
    }
}
