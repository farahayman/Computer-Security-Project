using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        int mod(int num, int modu)
        {
            return (num % modu + modu) % modu;
        }
        int[][] convertListToMatrix(List<int> key)
        {
            int n = key.Count();
            n = (int)Math.Sqrt(n);
            int m = key.Count() / n;
            int[][] matrix = new int[n][];
            for (int i = 0; i < key.Count(); i += n)
            {
                int[] temp = new int[m];
                for (int j = 0; j < m; j++)
                {
                    temp[j] = key[j + i];
                }
                matrix[i / n] = temp;
            }
            return matrix;
        }
        int det2by2Matrix(int[][] matrix)
        {
            return (matrix[0][0] * matrix[1][1]) - (matrix[0][1] * matrix[1][0]);
        }
        int det3by3Matrix(int[][] matrix)
        {
            int size = matrix.Length;
            int det = 0;
            for (int i = 0; i < size; i++)
            {
                int[][] temp = new int[size - 1][];
                List<int> t = new List<int>();
                for (int j = 1; j < size; j++)
                {
                    for (int k = 0; k < size; k++)
                    {
                        if (k == i) continue;
                        t.Add(matrix[j][k]);
                    }
                }
                temp = convertListToMatrix(t);
                int coff;
                if (i % 2 == 0) coff = 1;
                else coff = -1;
                det += (matrix[0][i] * det2by2Matrix(temp) * coff);
            }
            return det;
        }
        int multiplicativeInverse(int det)
        {
            int x = det;
            int i = 1;
            while (true)
            {
                if (mod(i * det, 26) == 1)
                {
                    x = i;
                    break;
                }
                i++;
            }
            return x;
        }
        int[][] transposeMat(int[][] matrix)
        {
            int size = matrix.Length;
            int[][] temp = new int[size][];
            for (int i = 0; i < size; i++)
            {
                int[] t = new int[size];
                for (int j = 0; j < size; j++)
                {
                    t[j] = matrix[j][i];
                }
                temp[i] = t;
            }
            return temp;
        }
        int[][] adjoint2by2Mat(int[][] matrix)
        {
            // TODO : {a,b,c,d} ==> {d,-b,-c,a}
            int t = matrix[0][0];
            matrix[0][0] = matrix[1][1];
            matrix[1][1] = t;
            matrix[0][1] *= -1;
            matrix[1][0] *= -1;
            for (int i = 0; i < matrix.Length; i++)
            {
                for (int j = 0; j < matrix.Length; j++)
                {
                    matrix[i][j] = mod(matrix[i][j], 26);
                }
            }
            return matrix;
        }
        int[][] adjoint3by3Mat(int[][] matrix)
        {
            int size = matrix.Length;
            List<int> adj = new List<int>();
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    int[][] temp = new int[size - 1][];
                    List<int> t = new List<int>();
                    for (int k = 0; k < size; k++)
                    {
                        for (int l = 0; l < size; l++)
                        {
                            if (k == i) break;
                            if (l == j) continue;
                            t.Add(matrix[k][l]);
                        }
                    }
                    temp = convertListToMatrix(t);
                    int coff;
                    if ((adj.Count()) % 2 == 0) coff = 1;
                    else coff = -1;
                    adj.Add(mod((det2by2Matrix(temp) * coff), 26));
                }
            }
            return convertListToMatrix(adj);
        }
        int[][] inverseMat(int[][] matrix, int determinant)
        {
            int size = matrix.Length;
            int[][] inv = new int[size][];
            for (int i = 0; i < size; i++)
            {
                int[] z = new int[size];
                for (int j = 0; j < size; j++)
                {
                    z[j] = mod((matrix[i][j] * determinant), 26);
                }
                inv[i] = z;
            }
            return inv;
        }
        List<int> convertMatrixToList(int[][] matrix)
        {
            int size = matrix.Length;
            List<int> L = new List<int>();
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    L.Add(matrix[i][j]);
                }
            }
            return L;
        }
        List<int> multipleMat(List<int> text, List<int> key)
        {
            List<int> res = new List<int>();
            int n = key.Count();
            n = (int)Math.Sqrt(n);
            for (int i = 0; i < text.Count(); i += n)
            {
                for (int j = 0; j < key.Count(); j += n)
                {
                    int x = 0;
                    for (int k = 0; k < n; k++)
                    {
                        x += key[j + k] * text[i + k];
                    }
                    res.Add(x % 26);
                }
            }
            return res;
        }
        int[][] multiply3by3Mat(List<int> mat1, List<int> mat2)
        {
            int[][] m1 = convertListToMatrix(mat1);
            int[][] m2 = convertListToMatrix(mat2);
            int[][] res = new int[3][];
            for (int i = 0; i < 3; i++)
            {
                int[] temp = new int[3];
                for (int j = 0; j < 3; j++)
                {
                    int t = 0;
                    for (int k = 0; k < 3; k++)
                    {
                        t += m1[i][k] * m2[k][j];
                    }
                    temp[j] = t;
                }
                res[i] = temp;
            }
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    res[i][j] = mod(res[i][j], 26);
                }
            }
            return res;
        }

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            // throw new NotImplementedException();
            //bruteforce algorithm
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            List<int> BruteKey = new List<int>();
                            BruteKey.Add(i);
                            BruteKey.Add(j);
                            BruteKey.Add(k);
                            BruteKey.Add(l);

                            List<int> Compare = Encrypt(plainText, BruteKey);
                            if (Compare.SequenceEqual(cipherText))
                                 return BruteKey;
                                
                            
                        }
                    }
                }
            
             }
            throw new InvalidAnlysisException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException
            // cipherText = cipherText.ToLower();
            List<int> plain = new List<int>();
            for (int i = 0; i < plainText.Length; i++)
            {
                plain.Add(plainText[i] - 97);
            }
            List<int> cipher = new List<int>();
            for (int i = 0; i < cipherText.Length; i++)
            {
                cipher.Add(cipherText[i] - 97);
            }
            List<int> key = Analyse(plain, cipher);
            string fin = "";
            for (int i = 0; i < key.Count; i++)
            {
                char c = (char)(key[i] + 97);
                fin += c;
            }
            return fin;
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            // Det/ - Transpose/ - adjoint - inverse
            List<int> decrypt = new List<int>();
            int[][] matrix = convertListToMatrix(key);
            int x = matrix.Length;
            int[][] inv = new int[x][];

            int det; // determinant 
            if (x == 2)
            {
                det = mod(det2by2Matrix(matrix), 26);
                if (det % 2 == 0)
                    throw new SystemException();
                int[][] adj = adjoint2by2Mat(matrix);
                inv = inverseMat(adj, det);
                //throw new SystemException();
            }
            else if (x == 3)
            {
                int[][] trans = transposeMat(matrix);
                det = mod(det3by3Matrix(matrix), 26);
                if (det % 2 == 0)
                    throw new SystemException();
                int mul = multiplicativeInverse(det);
                int[][] adj = adjoint3by3Mat(trans);
                inv = inverseMat(adj, mul);
            }
            List<int> keyInv = convertMatrixToList(inv);
            decrypt = multipleMat(cipherText, keyInv);
            return decrypt;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            List<int> cipher = new List<int>();
            for (int i = 0; i < cipherText.Length; i++)
            {
                cipher.Add(cipherText[i] - 97);
            }
            List<int> k = new List<int>();
            for (int i = 0; i < key.Length; i++)
            {
                k.Add(key[i] - 97);
            }
            List<int> dec = Decrypt(cipher, k);
            string fin = "";
            for (int i = 0; i < dec.Count; i++)
            {
                char c = (char)(dec[i] + 97);
                fin += c;
            }
            return fin;
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> encrypt = multipleMat(plainText, key);
            return encrypt;
        }

        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            List<int> plain = new List<int>();
            for (int i = 0; i < plainText.Length; i++)
            {
                plain.Add(plainText[i] - 97);
            }
            List<int> k = new List<int>();
            for (int i = 0; i < key.Length; i++)
            {
                k.Add(key[i] - 97);
            }
            List<int> cipher = Encrypt(plain, k);
            string fin = "";
            for (int i = 0; i < cipher.Count; i++)
            {
                char c = (char)(cipher[i] + 97);
                fin += c;
            }
            return fin.ToUpper();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            List<int> key = new List<int>();
            int[][] matrix = convertListToMatrix(plain3);
            int x = matrix.Length;
            int[][] inv = new int[x][];

            int det; // determinant 

            int[][] trans = transposeMat(matrix);
            det = mod(det3by3Matrix(matrix), 26);
            int mul = multiplicativeInverse(det);
            int[][] adj = adjoint3by3Mat(trans);
            inv = inverseMat(adj, mul);

            List<int> pinv = convertMatrixToList(inv);
            int[][] t = multiply3by3Mat(pinv, cipher3);
            int[][] temp = transposeMat(t);
            key = convertMatrixToList(temp);
            return key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            // throw new NotImplementedException();
            cipher3 = cipher3.ToLower();
            List<int> plain = new List<int>();
            for (int i = 0; i < plain3.Length; i++)
            {
                plain.Add(plain3[i] - 97);
            }
            List<int> cipher = new List<int>();
            for (int i = 0; i < cipher3.Length; i++)
            {
                cipher.Add(cipher3[i] - 97);
            }
            List<int> key = Analyse3By3Key(plain, cipher);
            string fin = "";
            for (int i = 0; i < key.Count; i++)
            {
                char c = (char)(key[i] + 97);
                fin += c;
            }
            return fin;
        }
    }
}
