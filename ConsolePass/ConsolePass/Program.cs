using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace ConsolePass
{
    class Program
    {
        private string loaded;
        private static bool Process;
        static Random rand;
        static void Main(string[] args)
        {
            // Some initialisation
            string userInput;
            Process = true;

            Console.Write("Enter pass: ");
            Login();

            Console.WriteLine("You are now logged in");
            //Print commands when logged in
            PrintCommands();

            while(Process)
            {
                userInput = Console.ReadLine();
                // convert to upper case as easier to handle
                userInput = userInput.ToUpper();
                ProcessCommands(userInput);
            }
        }

        // Login loop, once completed user will have entered the password and be able to request password list
        static void Login()
        {
            string password = "bob";
            string userInput;
            bool loggedIn = false;

            while (!loggedIn)
            {
                userInput = Console.ReadLine();
                if (userInput == password)
                {
                    //escape while loop
                    loggedIn = true;
                    PrintCommands();
                }
                else
                {
                    Console.WriteLine("Does not match");
                }
            }
        }

        // COMMAND INFO
        static void PrintCommands()
        {
            Console.WriteLine("Q to quit");
        }

        // all command handling happens here
        static void ProcessCommands(string input)
        {
            string[] userInput = input.Split(' ');
            switch (userInput[0])    // switch processes based on first phrase before a space
            {
                case "Q":                // Quit application
                    Process = false;
                    break;

                case "W":                // write some data
                    if (userInput.Length > 1)
                    {
                        Write(userInput[1]);
                    }
                    else
                    {
                        Console.WriteLine(" length must be > 1");
                    }
                    break;

                case "R":                // read some data
                    if (userInput.Length > 1)
                    {
                        Read("..\\" + userInput[1] + ".txt");
                    }
                    else
                    {
                        Console.Write(" length must be > 1");
                    }
                    break;

                case "G":               // Generate a string of set length
                    string temp = GenerateString(10);
                    Console.WriteLine(temp);
                    break;

                case "E":               // encrypt and decrypt a string
                    using (Aes myAes = Aes.Create())
                    {
                        byte[] nums = myAes.Key;
                        // always System.Byte[] can it not be stored?
                        Console.WriteLine("Key:     {0}", nums.ToString());
                        string original = userInput[1];
                        // Encrypt the string to an array of bytes.
                        byte[] encrypted = EncryptStringToBytes_Aes(original, myAes.Key, myAes.IV);
                        string enc = System.Text.Encoding.UTF32.GetString(encrypted, 0, encrypted.Length);
                        Write(enc);
                        //byte[] encryptedd = System.Text.Encoding.UTF32.GetBytes(enc);
                        // Decrypt the bytes to a string.
                        string roundtrip = DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);

                        //Display data
                       // string enc = System.Text.Encoding.UTF8.GetString(encrypted, 0, encrypted.Length);
                        Console.WriteLine("Original:   {0}", original);
                        Console.WriteLine("Encrypted: " + enc);
                        Console.WriteLine("Round Trip: {0}", roundtrip);
                    }
                    break;

                default:
                    break;
            }
        }

        // Write a line to a specified file
        static void Write(string toWrite)
        {
            string path = "..\\hash.txt";
            TextWriter tw = new StreamWriter(path, false);
            tw.Write(toWrite);
            tw.Close();
        }

        // Write an array to the file
        static void Write(string[] toWrite)
        {
            string path = "..\\hash.txt";
            TextWriter tw = new StreamWriter(path, false);
            for(int i = 0; i < toWrite.Length; i++)
            {
                tw.WriteLine(toWrite[i]);
            }
            tw.Close();
        }

        // Read from a specified file, return null = file not found
        static string Read(string path)
        {
            if(File.Exists(path))
            {
                TextReader tr = new StreamReader(path);
                string line = "";
                string fileContents = "";
                while ((line = tr.ReadLine()) != null)
                {
                    fileContents += line;
                }
                tr.Close();
                return fileContents;
            }
            else
            {
                return null;
            }
        }

        void Load()
        {
            loaded = Read("hash");
        }

        // Generates a string on a length passed in
        static string GenerateString(int length)
        {
            char[] potentialChar = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray();
            char[] randomString = new char[length];
            rand = new Random();

            // for however long specified pick a random char from potential char and build up salt array
            for (int i = 0; i < randomString.Length; i++)
            {
                randomString[i] = potentialChar[rand.Next(potentialChar.Length)];
            }

            string finalString = new string(randomString);
            return finalString;
        }


        static string Encrypt(string toEncrypt)
        {

            return toEncrypt;
        }

        // Microsoft stuff to use AES
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream.
            return encrypted;

        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }
    }
}
