using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WhoKnowsV2.util;
using WhoKnowsV2.Components;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Add in-memory distributed cache
builder.Services.AddDistributedMemoryCache();

// Add HttpClient for backend API
builder.Services.AddHttpClient("BackendAPI",client =>
{
    client.BaseAddress = new Uri("https://localhost:7100");
});

// Add session support
//builder.Services.AddSession(options =>
//{
//    options.IdleTimeout = TimeSpan.FromMinutes(30); // Set session timeout
//    options.Cookie.HttpOnly = true;
//    options.Cookie.IsEssential = true;
//});

// Add Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = "Cookies";
    options.DefaultChallengeScheme = "Cookies";
})
.AddCookie("Cookies", options =>
{
    options.LoginPath = "/login"; // Redirects to the login page if not authenticated
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
});

// Add Authorization
builder.Services.AddAuthorization();
builder.Services.AddScoped<ProtectedLocalStorage>();
builder.Services.AddScoped<ApiAuthenticationStateProvider>(); // Use Scoped instead of Transient
builder.Services.AddScoped<AuthenticationStateProvider, ApiAuthenticationStateProvider>();
builder.Services.AddAuthorizationCore(options =>
{
    options.AddPolicy("AllowAnonymous", policy =>
    {
        policy.RequireAssertion(context => true); // Allow everyone
    });
});



var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
