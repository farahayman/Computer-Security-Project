using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {

            //  throw new NotImplementedException();
            // throw new NotImplementedException();
            int[,] PC_round1 = new int[8, 7] {
                { 57, 49, 41, 33, 25, 17, 9 },
                { 1, 58, 50, 42, 34, 26, 18 },
                { 10, 2, 59, 51, 43, 35, 27 },
                { 19, 11, 3, 60, 52, 44, 36 },
                { 63, 55, 47, 39, 31, 23, 15 },
                { 7, 62, 54, 46, 38, 30, 22 },
                { 14, 6, 61, 53, 45, 37, 29 },
                { 21, 13, 5, 28, 20, 12, 4 } };
            int[,] PC_round2 = new int[8, 6] {
                { 14, 17, 11, 24, 1, 5 },
                { 3, 28, 15, 6, 21, 10 },
                { 23, 19, 12, 4, 26, 8 },
                { 16, 7, 27, 20, 13, 2 },
                { 41, 52, 31, 37, 47, 55 },
                { 30, 40, 51, 45, 33, 48 },
                { 44, 49, 39, 56, 34, 53 },
                { 46, 42, 50, 36, 29, 32 } };
            int[,] InitialPermutation = new int[8, 8] {
                { 58, 50, 42, 34, 26, 18, 10, 2 },
                { 60, 52, 44, 36, 28, 20, 12, 4 },
                { 62, 54, 46, 38, 30, 22, 14, 6 },
                { 64, 56, 48, 40, 32, 24, 16, 8 },
                { 57, 49, 41, 33, 25, 17, 9, 1 },
                { 59, 51, 43, 35, 27, 19, 11, 3 },
                { 61, 53, 45, 37, 29, 21, 13, 5 },
                { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] ExpansionPermutation = new int[8, 6] {
                { 32, 1, 2, 3, 4, 5 },
                { 4, 5, 6, 7, 8, 9 },
                { 8, 9, 10, 11, 12, 13 },
                { 12, 13, 14, 15, 16, 17 },
                { 16, 17, 18, 19, 20, 21 },
                { 20, 21, 22, 23, 24, 25 },
                { 24, 25, 26, 27, 28, 29 },
                { 28, 29, 30, 31, 32, 1 } };
            //sboxes
            int[,] sBox1 = new int[4, 16] {
                { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] sBox2 = new int[4, 16] {
                { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] sBox3 = new int[4, 16] {
                { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] sBox4 = new int[4, 16] {
                { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] sBox5 = new int[4, 16] {
                { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] sBox6 = new int[4, 16] {
                { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] sBox7 = new int[4, 16] {
                { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] sBox8 = new int[4, 16] {
                { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            int[,] Permutation = new int[8, 4] {
                { 16, 7, 20, 21 },
                { 29, 12, 28, 17 },
                { 1, 15, 23, 26 },
                { 5, 18, 31, 10 },
                { 2, 8, 24, 14 },
                { 32, 27, 3, 9 },
                { 19, 13, 30, 6 },
                { 22, 11, 4, 25 } };
            int[,] InitialPermutation_inverse = new int[8, 8] {
                { 40, 8, 48, 16, 56, 24, 64, 32 },
                { 39, 7, 47, 15, 55, 23, 63, 31 },
                { 38, 6, 46, 14, 54, 22, 62, 30 },
                { 37, 5, 45, 13, 53, 21, 61, 29 },
                { 36, 4, 44, 12, 52, 20, 60, 28 },
                { 35, 3, 43, 11, 51, 19, 59, 27 },
                { 34, 2, 42, 10, 50, 18, 58, 26 },
                { 33, 1, 41, 9, 49, 17, 57, 25 } };


            //1-convert them to 64 bit base 16
            string binary_cipher = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string KeyBit = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            //2-using pc round 1 for premutate key 
            string tempRes = null;
            List<string> C_list = new List<string>();
            List<string> D_list = new List<string>();

            for (int i = 0; i < 8; i++)
            {
                int j = 0;
                do
                {
                    tempRes += KeyBit[PC_round1[i, j] - 1];
                    j++;
                }
                while (j < 7);

            }

            //3-creating 2 lists (divide the plaintext by 2 )
            // c from 0 to 27
            // D from 28 to 56
            string c = tempRes.Substring(0, 28);
            string d = tempRes.Substring(28, 28);
            //4-left circular shift to get 56 bits
            string Res = null;
            int p = 0;
            while (p <= 16)
            {
                C_list.Add(c);
                D_list.Add(d);
                Res = null;
                if (p == 0 || p == 1 || p == 8 || p == 15)   //left circular shift 1 bit
                {
                    Res += c[0];
                    c = c.Remove(0, 1);
                    c += Res;
                    Res = null;
                    Res += d[0];
                    d = d.Remove(0, 1);
                    d += Res;
                }

                else if (p != 0 || p != 1 || p != 8 || p != 15)    //left circular shift 2 bits
                {
                    Res += c.Substring(0, 2);
                    c = c.Remove(0, 2);
                    c += Res;
                    Res = "";
                    Res += d.Substring(0, 2);
                    d = d.Remove(0, 2);
                    d += Res;
                }
                p++;
            }

            int D_list_count = D_list.Count;
            List<string> Keyss_List = new List<string>();
            int Keys_list_count = Keyss_List.Count;
            int w = 0;
            while (w < D_list_count)
            {
                Keyss_List.Add(C_list[w] + D_list[w]);
                w++;
            }

            //5-get from key 1 to key 16 using Pc round 2
            // will get 56 bit using permutation choice 2 to be 48 bits only
            List<string> KeysNum = new List<string>();
            for (int e = 1; e < Keyss_List.Count; e++)
            {
                tempRes = null;
                Res = null;
                Res = Keyss_List[e];
                int i = 0;
                while (i < 8)
                {
                    int j = 0;
                    while (j < 6)
                    {
                        tempRes += Res[PC_round2[i, j] - 1];
                        j++;
                    }
                    i++;
                }

                KeysNum.Add(tempRes);
            }


            //6-get the 48 bits key after permuted choice 2 and the 64 bits plain text after premutation to make round 1 
            string initial_P = null;
            for (int i = 0; i < 8; i++)
            {
                int j = 0;
                while (j < 8)
                {
                    initial_P += binary_cipher[InitialPermutation[i, j] - 1];
                    j++;
                }
            }

            //7-divide the 64 bits by 2 to get 32 bits right and 32 bits left
            List<string> Left_List = new List<string>();
            List<string> Right_List = new List<string>();

            string l = initial_P.Substring(0, 32);      //from 0 to 31
            string r = initial_P.Substring(32, 32);     // from 32 to 64

            Left_List.Add(l);
            Right_List.Add(r);
            string xxx = null;
            string hhh = null;
            string exxbit = null, exoork = null;
            List<string> SBoxList = new List<string>();

            string ttt = null;
            int rows = 0;
            int cols = 0;
            string sss = null;
            string ppp = null;
            string lft = null;

            for (int i = 0; i < 16; i++)
            {
                Left_List.Add(r);
                exoork = null;
                exxbit = null;
                lft = null;
                ppp = null;
                SBoxList.Clear();
                sss = null;
                cols = 0;
                rows = 0;
                ttt = null;
                for (int j = 0; j < 8; j++)
                {
                    int k = 0;
                    while (k < 6)
                    {
                        exxbit += r[ExpansionPermutation[j, k] - 1];
                        k++;
                    }
                }
                int exxbit_Length = exxbit.Length;
                for (int g = 0; g < exxbit_Length; g++)
                {
                    exoork += (KeysNum[KeysNum.Count - 1 - i][g] ^ exxbit[g]).ToString();
                }

                for (int z = 0; z < exoork.Length; z = z + 6)
                {
                    ttt = null;
                    int y = z;
                    int sum = 6 + z;
                    while (y < sum)
                    {
                        if (6 + z <= exoork.Length)
                            ttt += exoork[y];
                        y++;
                    }
                    SBoxList.Add(ttt);
                }
                //sBoxes
                ttt = null;
                int sb = 0;
                for (int s = 0; s < SBoxList.Count; s++)
                {
                    ttt = SBoxList[s];
                    xxx = ttt[0].ToString() + ttt[5];
                    hhh = ttt[1].ToString() + ttt[2] + ttt[3] + ttt[4];

                    rows = Convert.ToInt32(xxx, 2);
                    cols = Convert.ToInt32(hhh, 2);
                    switch (s)
                    {
                        case 0:
                            {
                                sb = sBox1[rows, cols];
                                break;
                            }
                        case 1:
                            {
                                sb = sBox2[rows, cols];
                                break;
                            }
                        case 2:
                            {
                                sb = sBox3[rows, cols];
                                break;
                            }
                        case 3:
                            {
                                sb = sBox4[rows, cols];
                                break;
                            }
                        case 4:
                            {
                                sb = sBox5[rows, cols];
                                break;
                            }
                        case 5:
                            {
                                sb = sBox6[rows, cols];
                                break;
                            }
                        case 6:
                            {
                                sb = sBox7[rows, cols];
                                break;
                            }
                        case 7:
                            {
                                sb = sBox8[rows, cols];
                                break;
                            }

                    }

                    sss += Convert.ToString(sb, 2).PadLeft(4, '0');
                } // will get 32 bits 

                xxx = null;
                hhh = null;
                //make permutation on the 32 bits to change their order
                for (int k = 0; k < 8; k++)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        ppp += sss[Permutation[k, j] - 1];
                        j++;
                    }
                }

                for (int k = 0; k < ppp.Length; k++)
                {
                    lft += (ppp[k] ^ l[k]).ToString();
                }

                r = lft;
                l = Left_List[i + 1];
                Right_List.Add(r);
            }
            //finally we will combine the left side and the right side
            string final_R = Right_List[16];
            string final_L = Left_List[16];
            string final = final_R + final_L;
            string pText = null;
            int PQ = 0;
            do
            {
                int j = 0;
                while (j < 8)
                {
                    pText += final[InitialPermutation_inverse[PQ, j] - 1];
                    j++;
                }
                PQ++;
            }
            while (PQ < 8);
            string convert = Convert.ToInt64(pText, 2).ToString("X").PadLeft(16, '0'); ;
            string plt = "0x" + convert;

            return plt;


        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            int[,] PC_round1 = new int[8, 7] {
                { 57, 49, 41, 33, 25, 17, 9 },
                { 1, 58, 50, 42, 34, 26, 18 },
                { 10, 2, 59, 51, 43, 35, 27 },
                { 19, 11, 3, 60, 52, 44, 36 },
                { 63, 55, 47, 39, 31, 23, 15 },
                { 7, 62, 54, 46, 38, 30, 22 },
                { 14, 6, 61, 53, 45, 37, 29 },
                { 21, 13, 5, 28, 20, 12, 4 } };
            int[,] PC_round2 = new int[8, 6] {
                { 14, 17, 11, 24, 1, 5 },
                { 3, 28, 15, 6, 21, 10 },
                { 23, 19, 12, 4, 26, 8 },
                { 16, 7, 27, 20, 13, 2 },
                { 41, 52, 31, 37, 47, 55 },
                { 30, 40, 51, 45, 33, 48 },
                { 44, 49, 39, 56, 34, 53 },
                { 46, 42, 50, 36, 29, 32 } };
            int[,] InitialPermutation = new int[8, 8] {
                { 58, 50, 42, 34, 26, 18, 10, 2 },
                { 60, 52, 44, 36, 28, 20, 12, 4 },
                { 62, 54, 46, 38, 30, 22, 14, 6 },
                { 64, 56, 48, 40, 32, 24, 16, 8 },
                { 57, 49, 41, 33, 25, 17, 9, 1 },
                { 59, 51, 43, 35, 27, 19, 11, 3 },
                { 61, 53, 45, 37, 29, 21, 13, 5 },
                { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] ExpansionPermutation = new int[8, 6] {
                { 32, 1, 2, 3, 4, 5 },
                { 4, 5, 6, 7, 8, 9 },
                { 8, 9, 10, 11, 12, 13 },
                { 12, 13, 14, 15, 16, 17 },
                { 16, 17, 18, 19, 20, 21 },
                { 20, 21, 22, 23, 24, 25 },
                { 24, 25, 26, 27, 28, 29 },
                { 28, 29, 30, 31, 32, 1 } };
            //sboxes
            int[,] sBox1 = new int[4, 16] {
                { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] sBox2 = new int[4, 16] {
                { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] sBox3 = new int[4, 16] {
                { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] sBox4 = new int[4, 16] {
                { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] sBox5 = new int[4, 16] {
                { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] sBox6 = new int[4, 16] {
                { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] sBox7 = new int[4, 16] {
                { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] sBox8 = new int[4, 16] {
                { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            int[,] Permutation = new int[8, 4] {
                { 16, 7, 20, 21 },
                { 29, 12, 28, 17 },
                { 1, 15, 23, 26 },
                { 5, 18, 31, 10 },
                { 2, 8, 24, 14 },
                { 32, 27, 3, 9 },
                { 19, 13, 30, 6 },
                { 22, 11, 4, 25 } };
            int[,] InitialPermutation_inverse = new int[8, 8] {
                { 40, 8, 48, 16, 56, 24, 64, 32 },
                { 39, 7, 47, 15, 55, 23, 63, 31 },
                { 38, 6, 46, 14, 54, 22, 62, 30 },
                { 37, 5, 45, 13, 53, 21, 61, 29 },
                { 36, 4, 44, 12, 52, 20, 60, 28 },
                { 35, 3, 43, 11, 51, 19, 59, 27 },
                { 34, 2, 42, 10, 50, 18, 58, 26 },
                { 33, 1, 41, 9, 49, 17, 57, 25 } };


            //1-convert them to 64 bit base 16
            string PtBit = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
            string KeyBit = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            string Leftm = null;
            string Rightm = null;
            int PTlength = PtBit.Length;
            int ii = 0;
            while (ii < PTlength / 2)
            {
                Leftm += PtBit[ii];
                Rightm += PtBit[ii + PTlength / 2];
                ii++;
            }

            //2-using pc round 1 for premutate key 
            string tempRes = null;
            List<string> C_list = new List<string>();
            List<string> D_list = new List<string>();

            for (int i = 0; i < 8; i++)
            {
                int j = 0;
                do
                {
                    tempRes += KeyBit[PC_round1[i, j] - 1];
                    j++;
                }
                while (j < 7);

            }

            //3-creating 2 lists (divide the plaintext by 2 )
            // c from 0 to 27
            // D from 28 to 56
            string c = tempRes.Substring(0, 28);
            string d = tempRes.Substring(28, 28);
            //4-left circular shift to get 56 bits
            string Res = null;
            int p = 0;
            while (p <= 16)
            {
                C_list.Add(c);
                D_list.Add(d);
                Res = null;
                if (p == 0 || p == 1 || p == 8 || p == 15)   //left circular shift 1 bit
                {
                    Res += c[0];
                    c = c.Remove(0, 1);
                    c += Res;
                    Res = null;
                    Res += d[0];
                    d = d.Remove(0, 1);
                    d += Res;
                }

                else if (p != 0 || p != 1 || p != 8 || p != 15)    //left circular shift 2 bits
                {
                    Res += c.Substring(0, 2);
                    c = c.Remove(0, 2);
                    c += Res;
                    Res = "";
                    Res += d.Substring(0, 2);
                    d = d.Remove(0, 2);
                    d += Res;
                }
                p++;
            }

            int D_list_count = D_list.Count;
            List<string> Keyss_List = new List<string>();
            int Keys_list_count = Keyss_List.Count;
            int w = 0;
            while (w < D_list_count)
            {
                Keyss_List.Add(C_list[w] + D_list[w]);
                w++;
            }

            //5-get from key 1 to key 16 using Pc round 2
            // will get 56 bit using permutation choice 2 to be 48 bits only
            List<string> KeysNum = new List<string>();
            for (int e = 1; e < Keyss_List.Count; e++)
            {
                tempRes = null;
                Res = null;
                Res = Keyss_List[e];
                int i = 0;
                while (i < 8)
                {
                    int j = 0;
                    while (j < 6)
                    {
                        tempRes += Res[PC_round2[i, j] - 1];
                        j++;
                    }
                    i++;
                }

                KeysNum.Add(tempRes);
            }


            //6-get the 48 bits key after permuted choice 2 and the 64 bits plain text after premutation to make round 1 
            string initial_P = null;
            for (int i = 0; i < 8; i++)
            {
                int j = 0;
                while (j < 8)
                {
                    initial_P += PtBit[InitialPermutation[i, j] - 1];
                    j++;
                }
            }

            //7-divide the 64 bits by 2 to get 32 bits right and 32 bits left
            List<string> Left_List = new List<string>();
            List<string> Right_List = new List<string>();

            string l = initial_P.Substring(0, 32);      //from 0 to 31
            string r = initial_P.Substring(32, 32);     // from 32 to 64

            Left_List.Add(l);
            Right_List.Add(r);
            string xxx = null;
            string hhh = null;
            string exxbit = null, exoork = null;
            List<string> SBoxList = new List<string>();

            string ttt = null;
            int rows = 0;
            int cols = 0;
            string sss = null;
            string ppp = null;
            string lft = null;

            for (int i = 0; i < 16; i++)
            {
                Left_List.Add(r);
                exoork = null;
                exxbit = null;
                lft = null;
                ppp = null;
                SBoxList.Clear();
                sss = null;
                cols = 0;
                rows = 0;
                ttt = null;
                for (int j = 0; j < 8; j++)
                {
                    int k = 0;
                    while (k < 6)
                    {
                        exxbit += r[ExpansionPermutation[j, k] - 1];
                        k++;
                    }
                }
                int exxbit_Length = exxbit.Length;
                for (int g = 0; g < exxbit_Length; g++)
                {
                    exoork += (KeysNum[i][g] ^ exxbit[g]).ToString();
                }

                for (int z = 0; z < exoork.Length; z = z + 6)
                {
                    ttt = null;
                    int y = z;
                    int sum = 6 + z;
                    while (y < sum)
                    {
                        if (6 + z <= exoork.Length)
                            ttt += exoork[y];
                        y++;
                    }
                    SBoxList.Add(ttt);
                }
                //sBoxes
                ttt = null;
                int sb = 0;
                for (int s = 0; s < SBoxList.Count; s++)
                {
                    ttt = SBoxList[s];
                    xxx = ttt[0].ToString() + ttt[5];
                    hhh = ttt[1].ToString() + ttt[2] + ttt[3] + ttt[4];

                    rows = Convert.ToInt32(xxx, 2);
                    cols = Convert.ToInt32(hhh, 2);
                    switch (s)
                    {
                        case 0:
                            {
                                sb = sBox1[rows, cols];
                                break;
                            }
                        case 1:
                            {
                                sb = sBox2[rows, cols];
                                break;
                            }
                        case 2:
                            {
                                sb = sBox3[rows, cols];
                                break;
                            }
                        case 3:
                            {
                                sb = sBox4[rows, cols];
                                break;
                            }
                        case 4:
                            {
                                sb = sBox5[rows, cols];
                                break;
                            }
                        case 5:
                            {
                                sb = sBox6[rows, cols];
                                break;
                            }
                        case 6:
                            {
                                sb = sBox7[rows, cols];
                                break;
                            }
                        case 7:
                            {
                                sb = sBox8[rows, cols];
                                break;
                            }

                    }

                    sss += Convert.ToString(sb, 2).PadLeft(4, '0');
                } // will get 32 bits 

                xxx = null;
                hhh = null;
                //make permutation on the 32 bits to change their order
                for (int k = 0; k < 8; k++)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        ppp += sss[Permutation[k, j] - 1];
                        j++;
                    }
                }

                for (int k = 0; k < ppp.Length; k++)
                {
                    lft += (ppp[k] ^ l[k]).ToString();
                }

                r = lft;
                l = Left_List[i + 1];
                Right_List.Add(r);
            }
            //finally we will combine the left side and the right side
            string final_R = Right_List[16];
            string final_L = Left_List[16];
            string final = final_R + final_L;
            string cipherText = null;
            int PQ = 0;
            do
            {
                int j = 0;
                while (j < 8)
                {
                    cipherText += final[InitialPermutation_inverse[PQ, j] - 1];
                    j++;
                }
                PQ++;
            }
            while (PQ < 8);
            string convert = Convert.ToInt64(cipherText, 2).ToString("X");
            string cipher = "0x" + convert;

            return cipher;
        }
    }
}
