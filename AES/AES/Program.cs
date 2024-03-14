using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        Console.WriteLine("AES Encryption/Decryption System");

        Console.WriteLine("Choose operation:");
        Console.WriteLine("1. Encrypt");
        Console.WriteLine("2. Decrypt");
        Console.WriteLine("0. Exit");
        Console.Write("Enter your choice: ");
        int choice = int.Parse(Console.ReadLine());

        switch (choice)
        {
            case 1:
                EncryptText();
                break;
            case 2:
                DecryptText();
                break;
            case 0:
                Console.WriteLine("Exiting program.");
                return;
            default:
                Console.WriteLine("Invalid choice.");
                break;
        }
    }

    static void EncryptText()
    {
        Console.Write("Enter plaintext: ");
        string plaintext = Console.ReadLine();

        Console.Write("Enter secret key: ");
        string key = Console.ReadLine();
        byte[] validKey = GetValidKey(key);

        Console.Write("Select encryption mode (ECB/CBC/CFB): ");
        string mode = Console.ReadLine().ToUpper();

        string encryptedText = Encrypt(plaintext, validKey, mode);
        Console.WriteLine("Encrypted text: " + encryptedText);

        string filename = "C:\\Users\\rolan\\source\\repos\\AES\\AES\\encrypted_text.txt";
        SaveToFile(filename, encryptedText);

        Console.WriteLine("Text encrypted and saved to file: " + filename);
    }

    static void DecryptText()
    {
        Console.Write("Enter filename to decrypt: ");
        string filename = Console.ReadLine();

        Console.Write("Enter secret key: ");
        string key = Console.ReadLine();
        byte[] validKey = GetValidKey(key);

        Console.Write("Select encryption mode (ECB/CBC/CFB): ");
        string mode = Console.ReadLine().ToUpper();

        string decryptedText = ReadFromFileAndDecrypt(filename, validKey, mode);
        Console.WriteLine("Decrypted text: " + decryptedText);

        string decryptedFilename = "C:\\Users\\rolan\\source\\repos\\AES\\AES\\decrypted_Text.txt";
        SaveToFile(decryptedFilename, decryptedText);

        Console.WriteLine("Text decrypted and saved to file: " + decryptedFilename);
    }

    static byte[] GetValidKey(string key)
    {
        using (var sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
        }
    }

    static string Encrypt(string plaintext, byte[] key, string mode)
    {
        byte[] iv = null;
        byte[] ciphertext;

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = mode switch
            {
                "ECB" => CipherMode.ECB,
                "CBC" => CipherMode.CBC,
                "CFB" => CipherMode.CFB,
                _ => throw new ArgumentException("Invalid mode")
            };

            if (mode == "CBC" || mode == "CFB")
            {
                aes.GenerateIV();
                iv = aes.IV;
            }

            using (MemoryStream ms = new MemoryStream())
            {
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                        cs.Write(plaintextBytes, 0, plaintextBytes.Length);
                    }
                }

                ciphertext = ms.ToArray();
            }
        }

        if (iv != null)
        {
            byte[] combined = new byte[iv.Length + ciphertext.Length];
            Array.Copy(iv, 0, combined, 0, iv.Length);
            Array.Copy(ciphertext, 0, combined, iv.Length, ciphertext.Length);
            return Convert.ToBase64String(combined);
        }
        else
        {
            return Convert.ToBase64String(ciphertext);
        }
    }

    static string Decrypt(byte[] ciphertext, byte[] key, string mode)
    {
        byte[] iv = null;
        byte[] plaintextBytes;

        if (mode == "CBC" || mode == "CFB")
        {
            iv = new byte[16];
            Array.Copy(ciphertext, 0, iv, 0, 16);
            ciphertext = ciphertext[16..];
        }

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = mode switch
            {
                "ECB" => CipherMode.ECB,
                "CBC" => CipherMode.CBC,
                "CFB" => CipherMode.CFB,
                _ => throw new ArgumentException("Invalid mode")
            };

            if (mode == "CBC" || mode == "CFB")
            {
                aes.IV = iv;
            }

            using (MemoryStream ms = new MemoryStream())
            {
                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(ciphertext, 0, ciphertext.Length);
                    }
                }

                plaintextBytes = ms.ToArray();
            }
        }

        return Encoding.UTF8.GetString(plaintextBytes);
    }

    static void SaveToFile(string filename, string ciphertext)
    {
        File.WriteAllText(filename, ciphertext);
    }

    static string ReadFromFileAndDecrypt(string filename, byte[] key, string mode)
    {
        byte[] ciphertext = Convert.FromBase64String(File.ReadAllText(filename));
        return Decrypt(ciphertext, key, mode);
    }
}
