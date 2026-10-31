using System.Diagnostics;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddProblemDetails();

var configuredToken = builder.Configuration["Authentication:Token"];
if (string.IsNullOrWhiteSpace(configuredToken))
{
  throw new InvalidOperationException("Authentication:Token must be configured.");
}

var app = builder.Build();

app.Use(async (context, next) =>
{
  var stopwatch = Stopwatch.StartNew();

  app.Logger.LogInformation(
    "Request started: {Method} {Path}",
    context.Request.Method,
    context.Request.Path);

  try
  {
    await next();
  }
  finally
  {
    stopwatch.Stop();

    app.Logger.LogInformation(
      "Request finished: {Method} {Path} responded {StatusCode} in {ElapsedMilliseconds} ms",
      context.Request.Method,
      context.Request.Path,
      context.Response.StatusCode,
      stopwatch.ElapsedMilliseconds);
  }
});

app.UseExceptionHandler();

app.UseWhen(
  context => context.Request.Path.StartsWithSegments("/users"),
  branch => branch.Use(async (context, next) =>
  {
    var authorizationHeader = context.Request.Headers.Authorization.ToString();
    const string bearerPrefix = "Bearer ";

    if (!authorizationHeader.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase))
    {
      await RejectUnauthorized(context, "A Bearer token is required.");
      return;
    }

    var providedToken = authorizationHeader[bearerPrefix.Length..].Trim();
    var expectedTokenBytes = Encoding.UTF8.GetBytes(configuredToken);
    var providedTokenBytes = Encoding.UTF8.GetBytes(providedToken);

    if (providedTokenBytes.Length != expectedTokenBytes.Length ||
        !CryptographicOperations.FixedTimeEquals(providedTokenBytes, expectedTokenBytes))
    {
      await RejectUnauthorized(context, "The provided token is invalid.");
      return;
    }

    await next();
  }));

var users = new List<User>();
var nextUserId = 1;

app.MapGet("/", () => "User Management API");

app.MapGet("/users", () => Results.Ok(users));

app.MapGet("/users/{id:int}", (int id) =>
{
  if (id <= 0)
  {
    return Results.BadRequest("User ID must be greater than zero.");
  }

  var user = users.FirstOrDefault(user => user.Id == id);
  return user is null ? Results.NotFound() : Results.Ok(user);
});

app.MapPost("/users", (CreateUserRequest request) =>
{
  var validationErrors = ValidateUserRequest(request);
  if (validationErrors.Count > 0)
  {
    return Results.ValidationProblem(validationErrors);
  }

  var user = new User(nextUserId++, request.Name, request.Email, request.Department);
  users.Add(user);

  return Results.Created($"/users/{user.Id}", user);
});

app.MapPut("/users/{id:int}", (int id, UpdateUserRequest request) =>
{
  if (id <= 0)
  {
    return Results.BadRequest("User ID must be greater than zero.");
  }

  var validationErrors = ValidateUserRequest(request);
  if (validationErrors.Count > 0)
  {
    return Results.ValidationProblem(validationErrors);
  }

  var userIndex = users.FindIndex(user => user.Id == id);
  if (userIndex < 0)
  {
    return Results.NotFound();
  }

  var updatedUser = new User(id, request.Name, request.Email, request.Department);
  users[userIndex] = updatedUser;

  return Results.Ok(updatedUser);
});

app.MapDelete("/users/{id:int}", (int id) =>
{
  if (id <= 0)
  {
    return Results.BadRequest("User ID must be greater than zero.");
  }

  var user = users.FirstOrDefault(user => user.Id == id);
  if (user is null)
  {
    return Results.NotFound();
  }

  users.Remove(user);
  return Results.NoContent();
});

static Dictionary<string, string[]> ValidateUserRequest(UserRequest request)
{
  var errors = new Dictionary<string, string[]>();

  if (string.IsNullOrWhiteSpace(request.Name))
  {
    errors["name"] = ["Name is required."];
  }
  else if (request.Name.Length > 100)
  {
    errors["name"] = ["Name must be 100 characters or fewer."];
  }

  if (string.IsNullOrWhiteSpace(request.Email))
  {
    errors["email"] = ["Email is required."];
  }
  else if (!new EmailAddressAttribute().IsValid(request.Email))
  {
    errors["email"] = ["Email must be a valid email address."];
  }
  else if (request.Email.Length > 254)
  {
    errors["email"] = ["Email must be 254 characters or fewer."];
  }

  if (string.IsNullOrWhiteSpace(request.Department))
  {
    errors["department"] = ["Department is required."];
  }
  else if (request.Department.Length > 100)
  {
    errors["department"] = ["Department must be 100 characters or fewer."];
  }

  return errors;
}

static async Task RejectUnauthorized(HttpContext context, string message)
{
  context.Response.StatusCode = StatusCodes.Status401Unauthorized;
  context.Response.Headers.WWWAuthenticate = "Bearer";
  await context.Response.WriteAsJsonAsync(new
  {
    error = "Unauthorized",
    message
  });
}

app.Run();

public record User(int Id, string Name, string Email, string Department);

public interface UserRequest
{
  string Name { get; }
  string Email { get; }
  string Department { get; }
}

public record CreateUserRequest(string Name, string Email, string Department) : UserRequest;

public record UpdateUserRequest(string Name, string Email, string Department) : UserRequest;
