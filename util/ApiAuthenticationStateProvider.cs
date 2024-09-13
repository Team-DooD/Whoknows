using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;

namespace WhoKnowsV2.util
{
    public class ApiAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly HttpClient _httpClient;
        private readonly ProtectedLocalStorage _localStorage;
        private readonly NavigationManager _navigationManager;
        private bool _isInitialized = false;
        private Task<AuthenticationState> _authenticationStateTask;

        public ApiAuthenticationStateProvider(HttpClient httpClient, ProtectedLocalStorage localStorage, NavigationManager navigationManager)
        {
            _httpClient = httpClient;
            _localStorage = localStorage;
            _navigationManager = navigationManager;
        }

        public async Task MarkUserAsAuthenticated(string token)
        {
            try
            {
                // Check for a valid token before proceeding
                if (string.IsNullOrWhiteSpace(token))
                {
                    throw new ArgumentException("Token cannot be null or empty", nameof(token));
                }

                // Save the token in local storage
                await _localStorage.SetAsync("authToken", token);

                // Parse claims and create identity
                var claims = ParseClaimsFromJwt(token);
                var identity = new ClaimsIdentity(claims, "jwt");

                // Ensure the ClaimsPrincipal is not null
                var authenticatedUser = new ClaimsPrincipal(identity);
                if (authenticatedUser == null)
                {
                    throw new InvalidOperationException("Failed to create ClaimsPrincipal.");
                }

                // Create the authentication state
                var authState = new AuthenticationState(authenticatedUser);

                // Notify that authentication state has changed
                NotifyAuthenticationStateChanged(Task.FromResult(authState));
            }
            catch (Exception ex)
            {
                // Log the exception if necessary
                Console.WriteLine($"Exception in MarkUserAsAuthenticated: {ex.Message}");

                // Optionally handle specific exceptions or rethrow
                throw;
            }
        }


        public async Task MarkUserAsLoggedOut()
        {
            await _localStorage.DeleteAsync("authToken");

            var anonymousUser = new ClaimsPrincipal(new ClaimsIdentity());
            var authState = Task.FromResult(new AuthenticationState(anonymousUser));
            NotifyAuthenticationStateChanged(authState);
        }

        public override Task<AuthenticationState> GetAuthenticationStateAsync()
     {
            if (_isInitialized)
            {
                return _authenticationStateTask;
            }

            _authenticationStateTask = GetAuthenticationStateInternal();
            _isInitialized = true;

            return _authenticationStateTask;
        }

        private async Task<AuthenticationState> GetAuthenticationStateInternal()
        {
            try
            {
                var result = await _localStorage.GetAsync<string>("authToken");
                var token = result.Success ? result.Value : null;

                // Prevent redirect loop
                var uri = _navigationManager.ToAbsoluteUri(_navigationManager.Uri);
                if (uri.LocalPath == "/Login")
                {
                    return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
                }

                if (string.IsNullOrWhiteSpace(token))
                {
                    return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
                }

                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

                var claims = ParseClaimsFromJwt(token);
                var identity = new ClaimsIdentity(claims, "jwt");
                var user = new ClaimsPrincipal(identity);

                return new AuthenticationState(user);
            }
            catch (Exception e)
            {
                // Log the exception if necessary
                Console.WriteLine($"Exception in GetAuthenticationStateInternal: {e.Message}");

                // Return anonymous state in case of error
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }
        }


        private IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
        {
            var payload = jwt.Split('.')[1];
            var jsonBytes = ParseBase64WithoutPadding(payload);
            var keyValuePairs = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonBytes);
            return keyValuePairs.Select(kvp => new Claim(kvp.Key, kvp.Value.ToString()));
        }

        private byte[] ParseBase64WithoutPadding(string base64)
        {
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            return Convert.FromBase64String(base64);
        }
    }
}
