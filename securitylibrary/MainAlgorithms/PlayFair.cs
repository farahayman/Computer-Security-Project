using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            key = key.ToLower();
            cipherText = cipherText.ToLower();
            char[,] matrix = new char[5, 5];
            int[] FreqArr = new int[26];
            int[] FreqArr2 = new int[26];
            char[] temp = new char[key.Length];
            int c = 0;
            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] >= 'a' && key[i] <= 'z')
                {
                    int x = (int)key[i] - 'a';
                    FreqArr[x]++;
                    if (FreqArr[x] > 1) FreqArr[x]--;
                    FreqArr2[x]++;
                    if (FreqArr2[x] == 1)
                    {
                        temp[c] = key[i];
                        c++;
                    }
                }


            }
            int ind = 0;

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (ind < c)
                    {
                        matrix[i, j] = temp[ind];
                        ind++;
                    }
                    else
                    {
                        for (int k = 0; k < 26; k++)
                        {
                            if (k == 8)
                            {
                                if (FreqArr[k] == 0 && FreqArr[k + 1] == 0)
                                    matrix[i, j] = (char)(k + 'a');
                                else k = k + 2;
                            }

                            if (FreqArr[k] == 0)
                            {
                                matrix[i, j] = (char)(k + 'a');
                                FreqArr[k]++;
                                break;
                            }
                        }
                    }

                }
            }
            char[] ctext;
            ctext = cipherText.ToCharArray();
            for (int i = 0; i < ctext.Length - 1; i += 2)
            {
                char x = ctext[i], y = ctext[i + 1];
                search_matrix2(ref x, ref y, matrix);
                ctext[i] = x;
                ctext[i + 1] = y;
            }

            string plainText = string.Join("", ctext);
            plainText = plainText.ToLower();
            int l = plainText.Length - 1;
            if (plainText[l] == 'x')
            {
                plainText = plainText.Remove(l,1);
            }
            int q = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i].Equals('x'))
                {
                    if (plainText[i - 1].Equals(plainText[i + 1]))
                    {
                        if ((i + q) % 2 != 0)
                        {
                            if (i - q < plainText.Length)
                            {
                                plainText = plainText.Remove(i, 1);
                                q++;
                            }
                        }
                    }
                }
            }

            Console.Write(plainText);
            return plainText;




        }
        static void search_matrix2(ref char x, ref char z, char[,] mat)
        {

            {
                int a = -1, b = -2, c = -3, d = -4;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (x == mat[i, j])
                        {
                            a = i;
                            b = j;
                        }
                        if (z == mat[i, j])
                        {
                            c = i;
                            d = j;
                        }

                    }
                }
                if (a == c)
                {
                    if (d == 0)
                    {
                        b = b - 1;
                        d = 4;

                    }
                    else if (b == 0)
                    {
                        b = 4;
                        d = d - 1;
                    }
                    else
                    {
                        b = b - 1;
                        d = d - 1;
                    }

                }
                else if (b == d)
                {
                    if (c == 0)
                    {
                        a = a - 1;
                        c = 4;
                    }
                    else if (a == 0)
                    {
                        a = 4;
                        c = c - 1;
                    }
                    else
                    {
                        a = a - 1;
                        c = c - 1;
                    }
                }
                else
                {
                    int t;
                    t = b;
                    b = d;
                    d = t;
                }
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (a == i && b == j)
                        {
                            x = mat[i, j];
                        }
                        else if (c == i && d == j)
                        {
                            z = mat[i, j];
                        }
                    }
                }
            }
        }

        static void search_matrix(ref char x, ref char z, char[,] mat)
        {

            {
                int a = -1, b = -2, c = -3, d = -4;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (x == mat[i, j])
                        {
                            a = i;
                            b = j;
                        }
                        if (z == mat[i, j])
                        {
                            c = i;
                            d = j;
                        }

                    }
                }
                if (a == c)
                {
                    if (d == 4)
                    {
                        b = b + 1;
                        d = 0;

                    }
                    else if (b == 4)
                    {
                        b = 0;
                        d = d + 1;
                    }
                    else
                    {
                        b = b + 1;
                        d = d + 1;
                    }

                }
                else if (b == d)
                {
                    if (c == 4)
                    {
                        a = a + 1;
                        c = 0;
                    }
                    else if (a == 4)
                    {
                        a = 0;
                        c = c + 1;
                    }
                    else
                    {
                        a = a + 1;
                        c = c + 1;
                    }
                }
                else
                {
                    int t;
                    t = b;
                    b = d;
                    d = t;
                }
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (a == i && b == j)
                        {
                            x = mat[i, j];
                        }
                        else if (c == i && d == j)
                        {
                            z = mat[i, j];
                        }
                    }
                }
            }

        }
        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            //char[] alphabeticChars = new char[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I','J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            key = key.ToLower();
            plainText = plainText.ToLower();
            char[,] matrix = new char[5, 5];
            int[] FreqArr = new int[26];
            int[] FreqArr2 = new int[26];
            char[] temp = new char[key.Length];
            int c = 0;
            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] >= 'a' && key[i] <= 'z')
                {
                    int x = (int)key[i] - 'a';
                    FreqArr[x]++;
                    if (FreqArr[x] > 1) FreqArr[x]--;
                    FreqArr2[x]++;
                    if (FreqArr2[x] == 1)
                    {
                        temp[c] = key[i];
                        c++;
                    }
                }


            }
            int ind = 0;

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (ind < c)
                    {
                        matrix[i, j] = temp[ind];
                        ind++;
                    }
                    else
                    {
                        for (int k = 0; k < 26; k++)
                        {
                            if (k == 8)
                            {
                                if (FreqArr[k] == 0 && FreqArr[k + 1] == 0)
                                    matrix[i, j] = (char)(k + 'a');
                                else k = k + 2;
                            }

                            if (FreqArr[k] == 0)
                            {
                                matrix[i, j] = (char)(k + 'a');
                                FreqArr[k]++;
                                break;
                            }
                        }
                    }

                }
            }
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Insert(i + 1, "x");
                }

            }

            if (plainText.Length % 2 != 0)
            {
                plainText = plainText + 'x';
            }
            char[] ptext;
            ptext = plainText.ToCharArray();
            for (int i = 0; i < ptext.Length; i += 2)
            {
                char x = ptext[i], y = ptext[i + 1];
                search_matrix(ref x, ref y, matrix);
                ptext[i] = x;
                ptext[i + 1] = y;
            }
            string cipherText = string.Join("", ptext);
            Console.Write(cipherText);
            return cipherText.ToUpper();

        }

    }
}





