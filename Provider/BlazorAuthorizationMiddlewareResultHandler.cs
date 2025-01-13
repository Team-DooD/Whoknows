using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace BlazorWhoknowsV2.Provider
{
    public class BlazorAuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
    {
        private readonly IAuthorizationService _authorizationService;
        private readonly IAuthorizationPolicyProvider _policyProvider;

        public BlazorAuthorizationMiddlewareResultHandler(
            IAuthorizationService authorizationService,
            IAuthorizationPolicyProvider policyProvider)
        {
            _authorizationService = authorizationService;
            _policyProvider = policyProvider;
        }

        public async Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
        {
            if (!authorizeResult.Succeeded)
            {
                // Handle authorization failure here
                // For example, redirect to login page or return 403 Forbidden

                if (context.User.Identity.IsAuthenticated)
                {
                    // User is authenticated but not authorized
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await context.Response.WriteAsync("You do not have permission to access this resource.");
                }
                else
                {
                    // User is not authenticated
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsync("You are not authenticated. Please log in.");
                }
                return;
            }

            // Authorization succeeded, proceed with the request
            await next(context);
        }
    }
}
