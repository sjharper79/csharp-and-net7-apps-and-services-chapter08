using CryptographyLib;
using System.Security;
using System.Security.Principal;
using System.Security.Claims;

Protector.Register("Alice", "Pa$$w0rd", new[] { "Admins" });
Protector.Register("Bob", "P@ssW0rd", new[] { "Sales", "TeamLeads" });
Protector.Register("Eve", "PassWORD");
Write("Enter your username: ");
string? username = ReadLine();
if (string.IsNullOrEmpty(username))
{
    WriteLine("You must enter a username.");
    return;
}
Write("Enter your password: ");
string? password = ReadLine();
if (string.IsNullOrEmpty(password))
{
    WriteLine("You must enter your password.");
    return;
}
Protector.LogIn(username, password);
if (Thread.CurrentPrincipal == null)
{
    WriteLine("Log in failed.");
    return;
}
IPrincipal p = Thread.CurrentPrincipal;
WriteLine($"IsAuthenticated: {p.Identity?.IsAuthenticated}");
WriteLine($"AuthenticationType: {p.Identity?.AuthenticationType}");
WriteLine($"Name: {p.Identity?.Name}");
WriteLine($"IsInRole(\"Admins\"): {p.IsInRole("Admins")}");
WriteLine($"IsInRole(\"Sales\"): {p.IsInRole("Sales")}");
if (p is ClaimsPrincipal)
{
    WriteLine($"{p.Identity?.Name} has the following claims:");
    IEnumerable<Claim>? claims = (p as ClaimsPrincipal)?.Claims;
    if (claims is not null)
    {
        foreach (Claim claim in claims)
        {
            WriteLine($"{claim.Type}: {claim.Value}");
        }
    }
}

try
{
    SecureFeature();
}
catch (Exception ex)
{
    WriteLine($"{ex.GetType()}: {ex.Message}");
}


