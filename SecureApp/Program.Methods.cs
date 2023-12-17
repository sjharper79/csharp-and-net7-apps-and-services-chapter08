using System.Security;

partial class Program
{
    static void SecureFeature()
    {
        if (Thread.CurrentPrincipal == null)
        {
            throw new SecurityException("A user must be logged in to access this feature.");
        }
        if (!Thread.CurrentPrincipal.IsInRole("Admins"))
        {
            throw new SecurityException("User must be a member of Admins to access this featrure.");
        }
        WriteLine("You have access to this secure feature.");
    }
}
