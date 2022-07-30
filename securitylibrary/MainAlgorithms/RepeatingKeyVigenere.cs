using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int n = cipherText.Length;
            int l = n - plainText.Length;
            //string k = key;

            string kstream = "";
            for (int j = 0; j < n; j++)
            {
                int x = (((int)cipherText[j] - 97) - ((int)plainText[j] - 97) + 26) % 26;
                x += 'a';
                kstream += (char)(x);
            }
            string k = "";
            k = k + kstream[0];
            for (int j = 1; j < kstream.Length; j++)
            {
                if (cipherText.Equals(Encrypt(plainText, k)))
                {

                    return k;
                }

                k += kstream[j];
            }
            return kstream;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            key = key.ToLower();
            cipherText = cipherText.ToLower();
            int n = cipherText.Length;
            int l = n - key.Length;
            //string k = key;

            for (int i = 0; i < l; i++)
            {
                if (i == key.Length - 1)
                    i = 0;
                if (key.Length == n)
                    break;
                key += (key[i]);
            }
            string p = "";
            for (int j = 0; j < n; j++)
            {
                int x = (((int)cipherText[j] - 97) - ((int)key[j] - 97) + 26) % 26;
                x += 'a';
                p += (char)(x);
            }
            return p;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            key = key.ToLower();
            plainText = plainText.ToLower();
            int n = plainText.Length;
            int l = n - key.Length;
            //string k = key;

            for (int i = 0; i < l; i++)
            {
                if (i == key.Length - 1)
                    i = 0;
                if (key.Length == n)
                    break;
                key += (key[i]);
            }
            string c = "";
            for (int j = 0; j < n; j++)
            {
                int x = (((int)plainText[j] - 97) + ((int)key[j] - 97)) % 26;
                x += 'a';
                c += (char)(x);
            }
            return c;
        }
    }
}