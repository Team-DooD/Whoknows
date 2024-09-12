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
        private NavigationManager _navigationManager;

        public ApiAuthenticationStateProvider(HttpClient httpClient, ProtectedLocalStorage localStorage, NavigationManager navigationManager)
        {
            _httpClient = httpClient;
            _localStorage = localStorage;
            _navigationManager = navigationManager;
        }

        public async Task MarkUserAsAuthenticated(string token)
        {
            // Save the token in local storage
            await _localStorage.SetAsync("authToken", token);

            var authenticatedUser = new ClaimsPrincipal(new ClaimsIdentity(ParseClaimsFromJwt(token), "jwt"));
            var authState = Task.FromResult(new AuthenticationState(authenticatedUser));

            NotifyAuthenticationStateChanged(authState);
        }


        public async Task MarkUserAsLoggedOut()
        {
            // Remove token from protected local storage
            await _localStorage.DeleteAsync("authToken");

            var anonymousUser = new ClaimsPrincipal(new ClaimsIdentity());
            var authState = Task.FromResult(new AuthenticationState(anonymousUser));
            NotifyAuthenticationStateChanged(authState);
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var result = await _localStorage.GetAsync<string>("authToken");
            var token = result.Success ? result.Value : null;

            var uri = _navigationManager.ToAbsoluteUri(_navigationManager.Uri);
            if (uri.LocalPath == "/Account/Login")
            {
                // Prevent redirect loop
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

            if (string.IsNullOrWhiteSpace(token))
            {
                // Return anonymous state if no token is present
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

            // Add token to default request headers
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            // Assuming you have a method to parse claims from JWT
            var claims = ParseClaimsFromJwt(token);
            var identity = new ClaimsIdentity(claims, "jwt");
            var user = new ClaimsPrincipal(identity);

            return new AuthenticationState(user);
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
