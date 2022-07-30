using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        String alpha = "abcdefghijklmnopqrstuvwxyz";
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            string ct = cipherText.ToLower();
            string pt = plainText.ToLower();
            string kstream = "";


            for (int i = 0; i < plainText.Length; i++)
            {
                int l1 = alpha.IndexOf(ct[i]);
                int l2 = alpha.IndexOf(pt[i]);
                int t = ((l1 - l2) + 26) % 26;

                kstream += alpha[t];

            }
            string k = "";
            k = k + kstream[0];
            for (int j = 1; j < kstream.Length; j++)
            {
                if (ct.Equals(Encrypt(pt, k)))
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


            string p = "";


            string k = key;
            for (int j = 0; j < n; j++)
            {
                if (k.Length == cipherText.Length)
                {
                    break;
                }
                int l1 = alpha.IndexOf(cipherText[j]);
                int l2 = alpha.IndexOf(k[j]);
                int t = ((l1 - l2) + 26) % 26;

                k += alpha[t];
            }
            for (int j = 0; j < n; j++)
            {
                int x1 = alpha.IndexOf(cipherText[j]);
                int x2 = alpha.IndexOf(k[j]);
                int t = ((x1 - x2) + 26) % 26;
                p += alpha[t];
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

                if (key.Length == n)
                    break;
                key += (plainText[i]);
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
