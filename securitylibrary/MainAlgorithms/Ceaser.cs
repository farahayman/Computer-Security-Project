using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            char[] PLAINTEXT = plainText.ToCharArray();
            char[] Cipher = new char[PLAINTEXT.Length];
            for (int i = 0; i < PLAINTEXT.Length; i++)
            {
                Cipher[i] = (char)(((int)PLAINTEXT[i] - 97 + key) % 26 + 97);
            }
            return new string(Cipher);
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            char[] CIPHERTEXT = cipherText.ToCharArray();
            char[] PlainTEXT = new char[CIPHERTEXT.Length];
            for (int i = 0; i < cipherText.Length; i++)
            {
                int asci_of_char = (int)CIPHERTEXT[i] - 97 - key;
                if (asci_of_char < 0)
                {
                    PlainTEXT[i] = (char)((asci_of_char + 26) + 97);
                }
                else
                {
                    PlainTEXT[i] = (char)(((asci_of_char) % 26) + 97);
                }
            }
            return new string(PlainTEXT);
        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int plainAscii = (int)plainText[0];
            int cipherAcii = (int)cipherText[0];
            if (cipherAcii - plainAscii < 0)
                return 26 + (cipherAcii - plainAscii);
            return cipherAcii - plainAscii;
        }
    }
}
