using CommerceWeb.Attributes;

namespace CommerceWeb.Middlewares
{
    public class CsrfValidationMiddleware
    {
        private readonly RequestDelegate _next;

        public CsrfValidationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var endpoint = context.GetEndpoint();
            var allowAnonymousCsrf = endpoint?.Metadata?.GetMetadata<AllowAnonymousCsrfAttribute>() != null;

            if (!allowAnonymousCsrf)
            {
                var protectedMethods = new[] { HttpMethods.Post, HttpMethods.Put, HttpMethods.Delete };
                if (protectedMethods.Contains(context.Request.Method))
                {
                    var csrfHeader = context.Request.Headers["X-XSRF-TOKEN"].FirstOrDefault();
                    var csrfCookie = context.Request.Cookies["XSRF-TOKEN"];

                    if (string.IsNullOrEmpty(csrfHeader) || csrfHeader != csrfCookie)
                    {
                        context.Response.StatusCode = StatusCodes.Status403Forbidden;
                        await context.Response.WriteAsync("CSRF validation failed.");
                        return;
                    }
                }
            }

            await _next(context);
        }
    }
}
