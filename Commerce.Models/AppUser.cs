using Microsoft.AspNetCore.Identity;

namespace Commerce.Models
{
    public class AppUser: IdentityUser
    {
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
