using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Amazix.Models;

namespace AmazixWeb.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        public UserController(UserManager<AppUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpGet]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<IActionResult> GetUser()
        {
            var userId = User.Claims.First(i => i.Type == ClaimTypes.NameIdentifier).Value;
            if (userId != null)
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    LoggedUserDto userDto = new LoggedUserDto
                    {
                        userGuid = user.Id,
                        email = user.Email
                    };
                    return Ok(userDto);
                }
            }
            return BadRequest(new { message = "Providing user details failed." });
        }
    }
}
