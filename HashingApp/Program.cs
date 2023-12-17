﻿using CryptographyLib;

WriteLine("Registering Alice with Pa$$2)rd:");
User alice = Protector.Register("Alice", "Pa$$w0rd");
WriteLine($"   Name: {alice.Name}");
WriteLine($"   Salt: {alice.Salt}");
WriteLine("    Password (salted and hashed): {0}", alice.SaltedHashedPassword);
WriteLine();
Write("Enter a new user to register: ");
string? username = ReadLine();
if (string.IsNullOrEmpty(username)) username = "Stephen";
Write($"Enter a password for {username}: ");
string? password = ReadLine();
if (string.IsNullOrEmpty(password)) password = "Pa$$w0rd";
WriteLine($"Registering new user {username}.");
User newUser = Protector.Register(username, password);
WriteLine($"   Name: {newUser.Name}");
WriteLine($"   Salt: {newUser.Salt}");
WriteLine("   Password (salted and hashed): {0}", newUser.SaltedHashedPassword);
WriteLine();
bool correctPassword = false;
while (!correctPassword)
{
    Write("Enter a username to log in: ");
    string? loginUsername = ReadLine();
    if (string.IsNullOrEmpty(loginUsername))
    {
        WriteLine("Login username cannot be empty.");
        Write("Press Ctrl+C to end or press ENTER to retry.");
        ReadLine();
        continue;
    }
    Write("Enter a password to log in: ");
    string? loginPassword = ReadLine();
    if (string.IsNullOrEmpty(loginPassword))
    {
        WriteLine("Login password cannot be empty.");
        Write("Press Ctrl+C to end or press ENTER to retry.");
        ReadLine(); continue;
    }
    correctPassword = Protector.CheckPassword(loginUsername, loginPassword);
    if (correctPassword)
    {
        WriteLine($"Correct! {loginUsername} has been logged in.");
    }
    else
    {
        WriteLine("Invalid username or password. Try again.");
    }
    WriteLine();
    WriteLine("Outputting all users.");
    Protector.OutputAllUsers();
}