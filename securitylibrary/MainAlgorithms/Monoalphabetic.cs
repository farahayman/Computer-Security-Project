using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        char[] array_alpha = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
        public string Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            char[] empty = new char[26];
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int PlainL = plainText.Length;
            int CipherL = cipherText.Length;
            for (int i = 0; i < PlainL; i++)
            {
                for (int k = 0; k < array_alpha.Length; k++)
                {
                    if (plainText[i] == array_alpha[k])
                    {
                        empty[k] = cipherText[i];
                    }
                }
            }

            for (int i = 0; i < empty.Length; i++)
            {
                if (empty[i] == '\0')
                {
                    for (int j = 0; j < array_alpha.Length; j++)
                    {
                        if (empty.Contains(array_alpha[j]))
                        {
                            array_alpha[j]++;
                        }
                        else
                        {
                            empty[i] = array_alpha[j];
                        }
                    }
                }
            }
            string emptyy = new string(empty);
            return emptyy;


        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            char[] plaintext = new char[cipherText.Length];
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[i] == key[j])
                    {
                        plaintext[i] = array_alpha[j];
                    }
                }
            }
            return new string(plaintext);
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            char[] ciphertext = new char[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (plainText[i] == array_alpha[j])
                    {
                        ciphertext[i] = key[j];
                    }
                }
            }
            return new string(ciphertext);
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();
            cipher = cipher.ToLower();
            char[] frequentKey = new char[cipher.Length];

            var dict = new Dictionary<char, int>();

            for (int i = 0; i < cipher.Length; i++)
            {
                if (dict.ContainsKey(cipher[i]))
                {
                    dict[cipher[i]]++;
                }
                else
                {
                    dict[cipher[i]] = 1;
                }
            }
            var sortedArr = from entry in dict orderby entry.Value ascending select entry.Key;
            char[] frequent = { 'z', 'q', 'j', 'x', 'k', 'v', 'b', 'y', 'w', 'g', 'p', 'f', 'm', 'u', 'c', 'd', 'l', 'h', 'r', 's', 'n', 'i', 'o', 'a', 't', 'e' };

            for (int c = 0; c < cipher.Length; c++)
            {
                int index = Array.IndexOf(sortedArr.ToArray(), cipher[c]);
                frequentKey[c] = frequent[index];
            }
            return new string(frequentKey);
        }
    }
}
