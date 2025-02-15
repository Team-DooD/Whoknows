﻿using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;

//namespace BlazorWhoknowsV2.Provider
//{
//    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
//    {
//        private readonly HttpClient _httpClient;
//        private readonly ILocalStorageService _localStorage;
//        private readonly string _tokenKey = "authToken";

//        public CustomAuthenticationStateProvider(HttpClient httpClient, ILocalStorageService localStorage)
//        {
//            _httpClient = httpClient;
//            _localStorage = localStorage;
//        }

//        // This method now always returns an authenticated state with a default claim
//        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
//        {
//            // Bypass the token check and always authenticate
//            var identity = new ClaimsIdentity(new[]
//            {
//                new Claim(ClaimTypes.Name, "Authenticated User"), // Example claim
//                new Claim(ClaimTypes.Role, "User") // Example role
//            }, "alwaysAuthType");

//            var user = new ClaimsPrincipal(identity);
//            return new AuthenticationState(user);
//        }

//        // MarkUserAsAuthenticated method remains unchanged if needed
//        public async Task MarkUserAsAuthenticated(string token)
//        {
//            await _localStorage.SetItemAsync(_tokenKey, token);
//            var claims = ParseClaimsFromJwt(token);
//            var identity = new ClaimsIdentity(claims, "jwtAuthType");
//            var user = new ClaimsPrincipal(identity);
//            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
//        }

//        // Logout method remains unchanged
//        public async Task Logout()
//        {
//            await _localStorage.RemoveItemAsync(_tokenKey);
//            _httpClient.DefaultRequestHeaders.Authorization = null;
//            var anonymousUser = new ClaimsPrincipal(new ClaimsIdentity());
//            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(anonymousUser)));
//        }

//        // Parse claims from JWT remains unchanged if needed for token processing
//        private IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
//        {
//            var payload = jwt.Split('.')[1];
//            var jsonBytes = ParseBase64WithoutPadding(payload);
//            var keyValuePairs = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonBytes);
//            return keyValuePairs.Select(kvp => new Claim(kvp.Key, kvp.Value.ToString()));
//        }

//        private byte[] ParseBase64WithoutPadding(string base64)
//        {
//            switch (base64.Length % 4)
//            {
//                case 2: base64 += "=="; break;
//                case 3: base64 += "="; break;
//            }
//            return Convert.FromBase64String(base64);
//        }
//    }
//}



//using Blazored.LocalStorage;
//using Microsoft.AspNetCore.Components.Authorization;
//using System.Net.Http.Headers;
//using System.Security.Claims;
//using System.Text.Json;


namespace BlazorWhoknowsV2.Provider
{

    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly HttpClient _httpClient;
        private readonly ILocalStorageService _localStorage;
        private readonly string _tokenKey = "authToken";

        public CustomAuthenticationStateProvider(HttpClient httpClient, ILocalStorageService localStorage)
        {
            _httpClient = httpClient;
            _localStorage = localStorage;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var token = await _localStorage.GetItemAsync<string>(_tokenKey);

            if (string.IsNullOrWhiteSpace(token))
            {
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var claims = ParseClaimsFromJwt(token);
            var identity = new ClaimsIdentity(claims, "jwtAuthType");
            var user = new ClaimsPrincipal(identity);

            return new AuthenticationState(user);
        }

        public async Task MarkUserAsAuthenticated(string token)
        {
            await _localStorage.SetItemAsync(_tokenKey, token);
            var claims = ParseClaimsFromJwt(token);
            var identity = new ClaimsIdentity(claims, "jwtAuthType");
            var user = new ClaimsPrincipal(identity);
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
        }

        public async Task Logout()
        {
            await _localStorage.RemoveItemAsync(_tokenKey);
            _httpClient.DefaultRequestHeaders.Authorization = null;
            var anonymousUser = new ClaimsPrincipal(new ClaimsIdentity());
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(anonymousUser)));
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
