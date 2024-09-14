using Blazored.LocalStorage;
using BlazorWhoknowsV2;
using BlazorWhoknowsV2.Data;
using BlazorWhoknowsV2.Pages;
using BlazorWhoknowsV2.Provider;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.IdentityModel.Tokens;
using System.Net.Http.Headers;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Configure JWT Bearer authentication
var jwtKey = builder.Configuration["Jwt:Key"];
var issuer = builder.Configuration["Jwt:Issuer"];
var audience = builder.Configuration["Jwt:Audience"];

if (string.IsNullOrEmpty(jwtKey))
{
    throw new ArgumentNullException("Jwt:Key", "Jwt:Key configuration is missing or empty");
}

if (string.IsNullOrEmpty(issuer))
{
    throw new ArgumentNullException("Jwt:Issuer", "Jwt:Issuer configuration is missing or empty");
}

if (string.IsNullOrEmpty(audience))
{
    throw new ArgumentNullException("Jwt:Audience", "Jwt:Audience configuration is missing or empty");
}

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });

// Add services to the container
builder.Services.AddBlazoredLocalStorage();
builder.Services.AddScoped<CustomAuthenticationStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(provider => provider.GetRequiredService<CustomAuthenticationStateProvider>());
builder.Services.AddAuthorizationCore();

// Configure HttpClient for API requests
builder.Services.AddHttpClient("ApiClient", client =>
{
    client.BaseAddress = new Uri("https://localhost:7100"); // Ensure this matches your backend API URL
    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
})
.AddHttpMessageHandler<CustomHttpClientHandler>();

builder.Services.AddScoped<DelegatingHandler, CustomHttpClientHandler>();

builder.Services.AddRazorPages();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddSingleton<WeatherForecastService>();

var app = builder.Build();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAntiforgery(); // Consider enabling or configuring antiforgery based on your needs

app.UseAuthentication();  // Ensure authentication is enabled
app.UseAuthorization();   // Ensure authorization is enabled

app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

app.Run();
