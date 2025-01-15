using Microsoft.AspNetCore.Identity;

namespace Amazix.Models
{
    public class AppUser: IdentityUser
    {
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
