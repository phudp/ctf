using System;
using System.Security.Cryptography;
using System.Text;

class Brute
{
    static int GetSeed(string input)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return BitConverter.ToInt32(hash, 0);
    }

    static bool Simulate(int seed)
    {
        var rng = new Random(seed);
        int player = 0, joker = 0;

        while (player < 100 && joker < 100)
        {
            player += rng.Next(1, 7);   // [1, 6]
            joker  += rng.Next(5, 7);   // [5, 6]
        }

        return player > joker;
    }

    static void Main()
    {
        var charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        int maxLen = 5;

        foreach (var candidate in GenerateStrings(charset, maxLen))
        {
            var seed = GetSeed(candidate);
            Console.WriteLine($"[*] Trying seed: \"{candidate}\" (int: {seed})");
            if (Simulate(seed))
            {
                Console.WriteLine($"[+] Winning seed: {candidate}");
                break;
            }
        }
    }

    static IEnumerable<string> GenerateStrings(string chars, int maxLen)
    {
        for (int len = 5; len <= maxLen; len++)
        {
            foreach (var s in Recurse(chars, "", len))
                yield return s;
        }
    }

    static IEnumerable<string> Recurse(string chars, string prefix, int remaining)
    {
        if (remaining == 0)
        {
            yield return prefix;
            yield break;
        }

        foreach (var c in chars)
        {
            foreach (var s in Recurse(chars, prefix + c, remaining - 1))
                yield return s;
        }
    }
}
