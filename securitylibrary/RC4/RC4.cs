using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            byte[] T = new byte[256];
            byte[] S = new byte[256];
            byte Temp;
            byte[] plainbyte, keybyte, cipherbyte = new byte[cipherText.Length];
            bool isHexa = false;
            string plainText = "";
            if (cipherText[0] == '0' && cipherText[1] == 'x')
            {
                 plainText = "0x"; isHexa = true;
                 cipherbyte = new byte[cipherText.Length - 2];
                 keybyte = new byte[key.Length - 2];
                 plainbyte = new byte[cipherbyte.Length];
                // remove "0x" from cipherText and key
                string ciphWithout0x = "", keyWithout0x = "";
                for (int i = 2; i < cipherText.Length; i++)
                {
                    ciphWithout0x += cipherText[i];
                }
                for (int i = 2; i < key.Length; i++)
                {
                    keyWithout0x += key[i];
                }
                cipherbyte = StringToByteArray(ciphWithout0x);
                keybyte = StringToByteArray(keyWithout0x);


            }
            else
            {
                for (int i = 0; i < cipherText.Length; i++)
                {
                    cipherbyte[i] = Convert.ToByte(cipherText[i]);
                }
                keybyte = Encoding.ASCII.GetBytes(key);
                plainbyte = new byte[cipherbyte.Length];

            }
            for (int i = 0; i < 256; i++)
            {
                S[i] = (byte)i;
                T[i] = keybyte[i % keybyte.Length];
            }
            // first permutation
            int j = 0; 
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                Temp = S[i];
                S[i] = S[j];
                S[j] = Temp;

            }
            // second permutation
            j = 0;
            int a = 0;
            Temp = 0;
            int t = 0;
            byte k;
            int XORresult = 0;
            for (int i = 0; i < plainbyte.Length; i++)
            {
                a = (a + 1) % 256;
                j = (j + S[a]) % 256;
                Temp = S[a];
                S[a] = S[j];
                S[j] = Temp;
                t = (S[a] + S[j]) % 256;
                k = S[t];


                if (isHexa)
                {
                    XORresult = k ^ cipherbyte[i];
                    plainText += XORresult.ToString("x");

                }
                else
                    plainbyte[i] = (byte)(cipherbyte[i] ^ k);


            }
            if (!isHexa)
            {
                for (int i = 0; i < plainbyte.Length; i++)
                {
                    plainText += (char)(plainbyte[i]);
                }
            }
            return plainText;


        }

        public override  string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();

            string cipherText = "";
            byte[] S = new byte[256];
            byte[] T = new byte[256];
            byte[] plainbyte, keybyte, cipherbyte;
            bool isHexa = false;
            if (plainText[0] == '0' && plainText[1] == 'x')
            {
                cipherText = "0x"; isHexa = true;
                plainbyte = new byte[plainText.Length - 2];
                keybyte = new byte[key.Length - 2];
                cipherbyte = new byte[plainbyte.Length];
                // remove "0x" from plainText and key
                string plnWithout0x = "", keyWithout0x = "";
                for (int i = 2; i < plainText.Length; i++)
                {
                    plnWithout0x += plainText[i];
                }
                for (int i = 2; i < key.Length; i++)
                {
                    keyWithout0x += key[i];
                }
                plainbyte = StringToByteArray(plnWithout0x);
                keybyte = StringToByteArray(keyWithout0x);

            }
            else
            {
                plainbyte = Encoding.ASCII.GetBytes(plainText);
                keybyte = Encoding.ASCII.GetBytes(key);
                cipherbyte = new byte[plainbyte.Length];
            }
            for (int i = 0; i < 256; i++)
            {
                S[i] = (byte)i;
                T[i] = keybyte[i % keybyte.Length];
            }
            // first permutation
            int j = 0; byte Temp;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                Temp = S[i];
                S[i] = S[j];
                S[j] = Temp;

            }
            // second permutation
            j = 0;
            int a = 0;
            Temp = 0;
            int t = 0;
            byte k;
            int XORresult = 0;
            for (int i = 0; i < plainbyte.Length; i++)
            {
                a = (a + 1) % 256;
                j = (j + S[a]) % 256;
                Temp = S[a];
                S[a] = S[j];
                S[j] = Temp;
                t = (S[a] + S[j]) % 256;
                k = S[t];


                if (isHexa)
                {
                    XORresult = k ^ plainbyte[i];
                    cipherText += XORresult.ToString("x");

                }
                else
                    cipherbyte[i] = (byte)(plainbyte[i] ^ k);


            }
            if (!isHexa)
            {
                for (int i = 0; i < cipherbyte.Length; i++)
                {
                    cipherText += (char)(cipherbyte[i]);
                }
            }
            return cipherText;

        }
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
