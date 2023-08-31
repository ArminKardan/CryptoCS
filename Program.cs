using System;
using System.IO;
using System.Security.Cryptography;

class Program
{
        static byte[] Encrypt(byte[] input, string password)
        {
            // Generate a random salt
            byte[] salt = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }

            // Derive a key from the password and salt
            byte[] key;
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 1000))
            {
                key = pbkdf2.GetBytes(32);
            }

            // Encrypt the data using AES
            byte[] encryptedData;
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                aes.GenerateIV();

                using (var ms = new MemoryStream())
                {
                    ms.Write(salt, 0, salt.Length);
                    ms.Write(aes.IV, 0, aes.IV.Length);

                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(input, 0, input.Length);
                        cs.FlushFinalBlock();
                    }

                    encryptedData = ms.ToArray();
                }
            }

            return encryptedData;
        }

        static byte[] Decrypt(byte[] input, string password)
        {
            // Read the salt and IV from the encrypted data
            byte[] salt = new byte[16];
            byte[] iv = new byte[16];
            Array.Copy(input, salt, 16);
            Array.Copy(input, 16, iv, 0, 16);

            // Derive a key from the password and salt
            byte[] key;
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 1000))
            {
                key = pbkdf2.GetBytes(32);
            }

            // Decrypt the data
            byte[] decryptedData;
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(input, 32, input.Length - 32);
                        cs.FlushFinalBlock();
                    }

                    decryptedData = ms.ToArray();
                }
            }

            return decryptedData;
        }



    static void Main(string[] args)
    {
        byte[] dataToEncrypt = new byte[] { 0x01, 0x02, 0x03 };
        string password = "password";

        byte[] encryptedData = Encrypt(dataToEncrypt, password);
        Console.WriteLine("ENC:"+BitConverter.ToString(encryptedData));

        byte[] decryptedData = Decrypt(encryptedData, password);
        Console.WriteLine("DEC:"+BitConverter.ToString(decryptedData));

        Console.ReadLine();
    }
}
