using System.Security.Cryptography.X509Certificates;

using CryptographyLib;
Write("How many times do you want to run this app: ");
string? times = ReadLine();
if (string.IsNullOrEmpty(times))
{
    WriteLine("You need to enter a number of times to run the app.");
    return;
}
int? count = int.Parse(times);
for (int c = 0; c < count; c++)
{
    Write("How big do you want the key (in bytes): ");
    string? size = ReadLine();
    if (string.IsNullOrEmpty(size))
    {
        WriteLine("You must enter a size for the key.");
        return;
    }

    byte[] key = Protector.GetRandomKeyOrIV(int.Parse(size));
    WriteLine($"Key as byte array:");
    for (int i = 0; i < key.Length; i++)
    {
        Write($"{key[i]:x2} ");
        if ((i + 1) % 16 == 0) WriteLine();
    }
    WriteLine();
}