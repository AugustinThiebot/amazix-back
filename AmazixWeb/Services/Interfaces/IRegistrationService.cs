using Amazix.Models;
using Microsoft.AspNetCore.Identity;

namespace AmazixWeb.Services.Interfaces
{
    public interface IRegistrationService
    {
        Task<IdentityResult> RegisterUserAsync(UserForRegistrationDto userDto, string scheme);
        Task<IdentityResult> ConfirmEmailAsync(string userId, string token);
    }
}
