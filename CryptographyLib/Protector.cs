using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Security.Principal;
using static System.Convert;

namespace CryptographyLib;
public class Protector
{
    private static readonly byte[] salt =
        Encoding.Unicode.GetBytes("7BANANAS");
    private static Dictionary<string, User> Users = new();
    private static readonly int iterations = 150_000;
    public static string? PublicKey;
    public static string Encrypt(string plainText, string password)
    {
        byte[] encryptedBytes;
        byte[] plainBytes = Encoding.Unicode.GetBytes(plainText);

        using (Aes aes = Aes.Create())
        {
            Stopwatch timer = Stopwatch.StartNew();

            using (Rfc2898DeriveBytes pbkdf2 = new(
                password, salt, iterations, HashAlgorithmName.SHA256))
            {
                Debug.WriteLine("PBKDF2 algorithm: {0}, Iteration count: {1:N0}",
                    pbkdf2.HashAlgorithm, pbkdf2.IterationCount);
                aes.Key = pbkdf2.GetBytes(32);
                aes.IV = pbkdf2.GetBytes(16);

            }
            timer.Stop();
            Debug.WriteLine("{0:N0} milliseconds to generate Key and IV.",
                timer.ElapsedMilliseconds);

            Debug.WriteLine("Encryptiong algorithm: {0}-{1}, {2} mode with {3} padding.",
                "AES", aes.KeySize, aes.Mode, aes.Padding);

            using (MemoryStream ms = new())
            {
                using (ICryptoTransform transformer = aes.CreateEncryptor())
                {
                    using (CryptoStream cs = new(
                        ms, transformer, CryptoStreamMode.Write))
                    {
                        cs.Write(plainBytes, 0, plainBytes.Length);

                        if (!cs.HasFlushedFinalBlock)
                        {
                            cs.FlushFinalBlock();
                        }
                    }
                }
                encryptedBytes = ms.ToArray();
            }
        }
        return ToBase64String(encryptedBytes);
    }
    public static string Decrypt(
        string cipherText, string password)
    {
        byte[] plainBytes;
        byte[] cryptoBytes = FromBase64String(cipherText);

        using (Aes aes = Aes.Create())
        {
            using (Rfc2898DeriveBytes pbkdf2 = new(
                password, salt, iterations, HashAlgorithmName.SHA256))
            {
                aes.Key = pbkdf2.GetBytes(32);
                aes.IV = pbkdf2.GetBytes(16);
            }
            using (MemoryStream ms = new MemoryStream())
            {
                using (ICryptoTransform transformer = aes.CreateDecryptor())
                {
                    using (CryptoStream cs = new(
                        ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cryptoBytes, 0, cryptoBytes.Length);

                        if (!cs.HasFlushedFinalBlock)
                        {
                            cs.FlushFinalBlock();
                        }
                    }
                }
                plainBytes = ms.ToArray();
            }
        }
        return Encoding.Unicode.GetString(plainBytes);
    }
    public static User Register(string username, string password, string[]? roles = null)
    {
        RandomNumberGenerator rng = RandomNumberGenerator.Create();
        byte[] saltBytes = new byte[16];
        rng.GetBytes(saltBytes);
        string saltText = ToBase64String(saltBytes);
        string saltedHashedPassword = SaltAndHashPassword(password, saltText);
        User user = new User(username, saltText, saltedHashedPassword, roles);
        Users.Add(user.Name, user);
        return user;
    }
    public static bool CheckPassword(string username, string password)
    {
        if (!Users.ContainsKey(username)) return false;
        User u = Users[username];
        return CheckPassword(password, u.Salt, u.SaltedHashedPassword);
    }
    public static bool CheckPassword(string password, string salt, string hashedPassword)
    {
        string saltedhashedPassword = SaltAndHashPassword(password, salt);
        return (saltedhashedPassword == hashedPassword);
    }
    private static string SaltAndHashPassword(string password, string salt)
    {
        using (SHA256 sha = SHA256.Create())
        {
            string saltedPassword = password + salt;
            return ToBase64String(sha.ComputeHash(
                Encoding.Unicode.GetBytes(saltedPassword)));
        }
    }
    public static void OutputAllUsers()
    {
        foreach (User user in Users.Values)
        {
            OutputUser(user);
        }
    }
    public static void OutputUser(User user)
    {
        WriteLine($"User {user.Name}. Salt: {user.Salt}. SaltedHashedPassword: {user.SaltedHashedPassword}");
    }
    public static string GenerateSignature(string data)
    {
        byte[] dataBytes = Encoding.Unicode.GetBytes(data);
        SHA256 sha = SHA256.Create();
        byte[] hashedData = sha.ComputeHash(dataBytes);
        RSA rsa = RSA.Create();
        PublicKey = rsa.ToXmlString(false); //false means do not output private key
        return ToBase64String(rsa.SignHash(hashedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }
    public static bool ValidateSignature(string data, string signature)
    {
        if (PublicKey is null) return false;
        byte[] dataBytes = Encoding.Unicode.GetBytes(data);
        SHA256 sha = SHA256.Create();
        byte[] hashedData = sha.ComputeHash(dataBytes);
        byte[] signatureBytes = FromBase64String(signature);
        RSA rSA = RSA.Create();
        rSA.FromXmlString(PublicKey);
        return rSA.VerifyHash(hashedData, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
    public static byte[] GetRandomKeyOrIV(int size)
    {
        RandomNumberGenerator r = RandomNumberGenerator.Create();
        byte[] data = new byte[size];
        r.GetBytes(data);
        return data;
    }
    public static void LogIn(string username, string password)
    {
        if (CheckPassword(username, password))
        {
            GenericIdentity gi = new(
                name: username, type: "PacktAuth");
            GenericPrincipal gp = new(
                identity: gi, roles: Users[username].Roles);
            Thread.CurrentPrincipal = gp;
        }
    }

}
