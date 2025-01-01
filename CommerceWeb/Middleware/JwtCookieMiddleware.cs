namespace CommerceWeb.Middleware
{
    public class JwtCookieMiddleware
    {
        private readonly RequestDelegate _next;
        public JwtCookieMiddleware(RequestDelegate next)
        {
            _next = next;
        }
        public async Task InvokeAsync(HttpContext context)
        {
            if (context.Request.Cookies.ContainsKey("auth_token"))
            {
                var token = context.Request.Cookies["auth_token"];
                context.Request.Headers.Add("Authorization", $"Bearer {token}");
            }
            await _next(context);
        }
    }
}
