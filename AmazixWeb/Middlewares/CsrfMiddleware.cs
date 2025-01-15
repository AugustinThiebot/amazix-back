namespace AmazixWeb.Middlewares
{
    public class CsrfMiddleware
    {
        private readonly RequestDelegate _next;

        public CsrfMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (!context.Request.Cookies.ContainsKey("XSRF-TOKEN"))
            {
                var csrfToken = Guid.NewGuid().ToString();
                context.Response.Cookies.Append("XSRF-TOKEN", csrfToken, new CookieOptions
                {
                    HttpOnly = false,
                    SameSite = SameSiteMode.None,
                    Secure = true
                });
            }
            await _next(context);
        }
    }

}
