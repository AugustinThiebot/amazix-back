namespace AmazixWeb.Middlewares
{
    public class JwtCookieMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _configuration;
        public JwtCookieMiddleware(RequestDelegate next, IConfiguration configuration)
        {
            _next = next;
            _configuration = configuration;
        }
        public async Task InvokeAsync(HttpContext context)
        {
            var jwtSettings = _configuration.GetSection("Jwt");
            if (context.Request.Cookies.ContainsKey(jwtSettings["Name"]))
            {
                var token = context.Request.Cookies[jwtSettings["Name"]];
                context.Request.Headers.Add("Authorization", $"Bearer {token}");
            }
            await _next(context);
        }
    }
}
