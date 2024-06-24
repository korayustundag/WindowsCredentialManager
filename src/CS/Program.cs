using System;

class Program
{
    static void Main(string[] args)
    {
        string target = "MyApp";
        string username = "user";
        string password = "password";

        // Add credential
        try
        {
            CredentialManager.AddCredential(target, username, password);
            Console.WriteLine("Credential added successfully.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to add credential: {ex.Message}");
        }

        // Read credential
        try
        {
            var credential = CredentialManager.ReadCredential(target);
            if (credential.HasValue)
            {
                Console.WriteLine("Read credential successfully.");
                Console.WriteLine($"Username: {credential.Value.username}");
                Console.WriteLine($"Password: {credential.Value.password}");
            }
            else
            {
                Console.WriteLine("Failed to read credential.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to read credential: {ex.Message}");
        }

        // Validate credential
        try
        {
            bool valid = CredentialManager.ValidateCredential(target, username, password);
            Console.WriteLine(valid ? "Credential validation successful." : "Credential validation failed.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to validate credential: {ex.Message}");
        }

        // Delete credential
        try
        {
            CredentialManager.DeleteCredential(target);
            Console.WriteLine("Credential deleted successfully.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to delete credential: {ex.Message}");
        }
    }
}
