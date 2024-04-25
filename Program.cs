using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using MinimalApi.Data;
using MinimalApi.Models;
using MiniValidation;
using NetDevPack.Identity.Jwt;
using NetDevPack.Identity.Model;

var builder = WebApplication.CreateBuilder(args);

#region Configure Services
// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddDbContext<MinimalContextDb>(options => 
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentityEntityFrameworkContextConfiguration(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
    b => b.MigrationsAssembly("MinimalApi")));

builder.Services.AddIdentityConfiguration();
builder.Services.AddJwtConfiguration(builder.Configuration, "AppJwtSettings");
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("DeleteProvider", policy => 
        policy.RequireClaim("DeleteProvider", "true"));
});

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Minimal API Sample",
        Description = "Developed by Rozaworks - Owner @ desenvolvedor.io",
        Contact = new OpenApiContact { Name = "Alan Roza", Email = "alancruzrozza@gmail.com" },
        License = new OpenApiLicense { Name = "MIT", Url = new Uri("https://opensource.org/licenses/MIT") }
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Insira o token JWT desta maneira: Bearer {seu token}",
        Name = "Authorization",
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

var app = builder.Build();
#endregion

#region Configure Pipeline
MapActions(app);

app.Run();
#endregion

#region Configure Actions
void MapActions(WebApplication app)
{
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseAuthConfiguration();
    app.UseHttpsRedirection();


    app.MapPost("/login", [AllowAnonymous] async (
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IOptions<AppJwtSettings> appJwtSettings,
        LoginUser loginUser) =>
    {
        if (loginUser == null)
            return Results.BadRequest("Usuário inválido");

        if (!MiniValidator.TryValidate(loginUser, out var errors))
            return Results.ValidationProblem(errors);

        var result = await signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, false, true);

        if (result.IsLockedOut)
            return Results.BadRequest("Usuário temporariamente bloqueado por tentativas inválidas");

        if (!result.Succeeded)
            return Results.BadRequest("Usuário ou senha inválidos");

        var jwt = new JwtBuilder()
                    .WithUserManager(userManager)
                    .WithJwtSettings(appJwtSettings.Value)
                    .WithEmail(loginUser.Email)
                    .WithJwtClaims()
                    .WithUserClaims()
                    .WithUserRoles()
                    .BuildUserResponse();

        return Results.Ok(jwt);
    })
        .ProducesValidationProblem()
        .Produces(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .WithName("UserLogin")
        .WithTags("User");

    app.MapPost("/register", [AllowAnonymous] async (
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IOptions<AppJwtSettings> appJwtSettings,
        RegisterUser registerUser) =>
    {
        if (registerUser == null)
            return Results.BadRequest("Usuário inválido");

        if (!MiniValidator.TryValidate(registerUser, out var errors))
            return Results.ValidationProblem(errors);

        var user = new IdentityUser
        {
            UserName = registerUser.Email,
            Email = registerUser.Email,
            EmailConfirmed = true
        };

        var result = await userManager.CreateAsync(user, registerUser.Password);

        if (!result.Succeeded)
            return Results.BadRequest(result.Errors);

        var jwt = new JwtBuilder()
                    .WithUserManager(userManager)
                    .WithJwtSettings(appJwtSettings.Value)
                    .WithEmail(user.Email)
                    .WithJwtClaims()
                    .WithUserClaims()
                    .WithUserRoles()
                    .BuildUserResponse();

        return Results.Ok(jwt);
    })
        .ProducesValidationProblem()
        .Produces(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .WithName("UserRegister")
        .WithTags("User");

    app.MapGet("/provider", [AllowAnonymous] async (
        MinimalContextDb context) =>
        await context.Providers.ToListAsync())
        .WithName("GetProvider")
        .WithTags("Provider");


    app.MapGet("/provider/{id}", [AllowAnonymous] async (
        Guid id,
        MinimalContextDb context) =>
        await context.Providers.FindAsync(id)
            is Provider provider
                ? Results.Ok(provider)
                : Results.NotFound()
            )
        .Produces<Provider>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status404NotFound)
        .WithName("GetProviderById")
        .WithTags("Provider");

    app.MapPost("/provider", [Authorize] async (
        MinimalContextDb context,
        Provider provider) =>
    {
        if (!MiniValidator.TryValidate(provider, out var errors))
            return Results.ValidationProblem(errors);

        context.Providers.Add(provider);
        var result = await context.SaveChangesAsync();

        return result > 0
            ? Results.CreatedAtRoute("GetProviderById", new { id = provider.Id }, provider)
            : Results.BadRequest("Houve um problema ao salvar o registro");
    })
        .ProducesValidationProblem()
        .Produces<Provider>(StatusCodes.Status201Created)
        .Produces(StatusCodes.Status404NotFound)
        .WithName("PostProvider")
        .WithTags("Provider");


    app.MapPut("/provider/{id}", [Authorize] async (
        Guid id,
        MinimalContextDb context,
        Provider provider) =>
    {
        var providerDb = await context.Providers.FindAsync(id);
        if (providerDb == null) return Results.NotFound();

        if (!MiniValidator.TryValidate(provider, out var errors))
            return Results.ValidationProblem(errors);

        context.Providers.Update(provider);
        var result = await context.SaveChangesAsync();

        return result > 0
            ? Results.NoContent()
            : Results.BadRequest("Houve um problema ao salvar o registro");
    })
        .ProducesValidationProblem()
        .Produces<Provider>(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status404NotFound)
        .WithName("PutProvider")
        .WithTags("Provider");

    app.MapDelete("/provider/{id}", [Authorize] async (
        Guid id,
        MinimalContextDb context) =>
    {
        var providerDb = await context.Providers.FindAsync(id);
        if (providerDb == null) return Results.NotFound();

        context.Providers.Remove(providerDb);
        var result = await context.SaveChangesAsync();

        return result > 0
            ? Results.NoContent()
            : Results.BadRequest("Houve um problema ao remover o registro");
    })
        .Produces<Provider>(StatusCodes.Status400BadRequest)
        .Produces<Provider>(StatusCodes.Status204NoContent)
        .Produces<Provider>(StatusCodes.Status404NotFound)
        .RequireAuthorization("DeleteProvider")
        .WithName("DeleteProvider")
        .WithTags("Provider");
}
#endregion