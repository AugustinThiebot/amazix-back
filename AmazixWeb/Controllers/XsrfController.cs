using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AmazixWeb.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class XsrfController : ControllerBase
    {
        [HttpGet("xsrf")]
        public IActionResult XSRFToken()
        {
            var csrfToken = Guid.NewGuid().ToString();
            Response.Cookies.Append("XSRF-TOKEN", csrfToken, new CookieOptions
            {
                HttpOnly = false,
                SameSite = SameSiteMode.None,
                Secure = true
            });
            return Ok();
        }
    }
}
