using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {

        public override string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            string cipher = "";
            string mainKey = "";
            string mainPlain = "0x";
            for (int i = 2; i < cipherText.Length; i++)
            {
                cipher += cipherText[i];
            }

            for (int i = 2; i < key.Length; i++)
            {
                mainKey += key[i];
            }
            string[,] Cipher_Matrix = new string[4, 4];
            int mainkeyCounter = 0;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    Cipher_Matrix[i, j] = cipher[mainkeyCounter].ToString();
                    mainkeyCounter++;
                    Cipher_Matrix[i, j] += cipher[mainkeyCounter].ToString();
                    mainkeyCounter++;
                }
            }
            string[,] InverseSbox = new string[16, 16];
            string[,] InverseMixColumnsMatrix = new string[4, 4];
            string[,] RConstant = new string[4, 10];
            string[,] Sbox = new string[16, 16];
            //Sbox
            FillSBox(ref Sbox);
            //Inverse Sbox
            #region InverseSbox

            InverseSbox[0, 0] = "52";
            InverseSbox[0, 1] = "09";
            InverseSbox[0, 2] = "6a";
            InverseSbox[0, 3] = "d5";
            InverseSbox[0, 4] = "30";
            InverseSbox[0, 5] = "36";
            InverseSbox[0, 6] = "a5";
            InverseSbox[0, 7] = "38";
            InverseSbox[0, 8] = "bf";
            InverseSbox[0, 9] = "40";
            InverseSbox[0, 10] = "a3";
            InverseSbox[0, 11] = "9e";
            InverseSbox[0, 12] = "81";
            InverseSbox[0, 13] = "f3";
            InverseSbox[0, 14] = "d7";
            InverseSbox[0, 15] = "fb";

            InverseSbox[1, 0] = "7c";
            InverseSbox[1, 1] = "e3";
            InverseSbox[1, 2] = "39";
            InverseSbox[1, 3] = "82";
            InverseSbox[1, 4] = "9b";
            InverseSbox[1, 5] = "2f";
            InverseSbox[1, 6] = "ff";
            InverseSbox[1, 7] = "87";
            InverseSbox[1, 8] = "34";
            InverseSbox[1, 9] = "8e";
            InverseSbox[1, 10] = "43";
            InverseSbox[1, 11] = "44";
            InverseSbox[1, 12] = "c4";
            InverseSbox[1, 13] = "de";
            InverseSbox[1, 14] = "e9";
            InverseSbox[1, 15] = "cb";

            InverseSbox[2, 0] = "54";
            InverseSbox[2, 1] = "7b";
            InverseSbox[2, 2] = "94";
            InverseSbox[2, 3] = "32";
            InverseSbox[2, 4] = "a6";
            InverseSbox[2, 5] = "c2";
            InverseSbox[2, 6] = "23";
            InverseSbox[2, 7] = "3d";
            InverseSbox[2, 8] = "ee";
            InverseSbox[2, 9] = "4c";
            InverseSbox[2, 10] = "95";
            InverseSbox[2, 11] = "0b";
            InverseSbox[2, 12] = "42";
            InverseSbox[2, 13] = "fa";
            InverseSbox[2, 14] = "c3";
            InverseSbox[2, 15] = "4e";

            InverseSbox[3, 0] = "08";
            InverseSbox[3, 1] = "2e";
            InverseSbox[3, 2] = "a1";
            InverseSbox[3, 3] = "66";
            InverseSbox[3, 4] = "28";
            InverseSbox[3, 5] = "d9";
            InverseSbox[3, 6] = "24";
            InverseSbox[3, 7] = "b2";
            InverseSbox[3, 8] = "76";
            InverseSbox[3, 9] = "5b";
            InverseSbox[3, 10] = "a2";
            InverseSbox[3, 11] = "49";
            InverseSbox[3, 12] = "6d";
            InverseSbox[3, 13] = "8b";
            InverseSbox[3, 14] = "d1";
            InverseSbox[3, 15] = "25";

            InverseSbox[4, 0] = "72";
            InverseSbox[4, 1] = "f8";
            InverseSbox[4, 2] = "f6";
            InverseSbox[4, 3] = "64";
            InverseSbox[4, 4] = "86";
            InverseSbox[4, 5] = "68";
            InverseSbox[4, 6] = "98";
            InverseSbox[4, 7] = "16";
            InverseSbox[4, 8] = "d4";
            InverseSbox[4, 9] = "a4";
            InverseSbox[4, 10] = "5c";
            InverseSbox[4, 11] = "cc";
            InverseSbox[4, 12] = "5d";
            InverseSbox[4, 13] = "65";
            InverseSbox[4, 14] = "b6";
            InverseSbox[4, 15] = "92";

            InverseSbox[5, 0] = "6c";
            InverseSbox[5, 1] = "70";
            InverseSbox[5, 2] = "48";
            InverseSbox[5, 3] = "50";
            InverseSbox[5, 4] = "fd";
            InverseSbox[5, 5] = "ed";
            InverseSbox[5, 6] = "b9";
            InverseSbox[5, 7] = "da";
            InverseSbox[5, 8] = "5e";
            InverseSbox[5, 9] = "15";
            InverseSbox[5, 10] = "46";
            InverseSbox[5, 11] = "57";
            InverseSbox[5, 12] = "a7";
            InverseSbox[5, 13] = "8d";
            InverseSbox[5, 14] = "9d";
            InverseSbox[5, 15] = "84";

            InverseSbox[6, 0] = "90";
            InverseSbox[6, 1] = "d8";
            InverseSbox[6, 2] = "ab";
            InverseSbox[6, 3] = "00";
            InverseSbox[6, 4] = "8c";
            InverseSbox[6, 5] = "bc";
            InverseSbox[6, 6] = "d3";
            InverseSbox[6, 7] = "0a";
            InverseSbox[6, 8] = "f7";
            InverseSbox[6, 9] = "e4";
            InverseSbox[6, 10] = "58";
            InverseSbox[6, 11] = "05";
            InverseSbox[6, 12] = "b8";
            InverseSbox[6, 13] = "b3";
            InverseSbox[6, 14] = "45";
            InverseSbox[6, 15] = "06";

            InverseSbox[7, 0] = "d0";
            InverseSbox[7, 1] = "2c";
            InverseSbox[7, 2] = "1e";
            InverseSbox[7, 3] = "8f";
            InverseSbox[7, 4] = "ca";
            InverseSbox[7, 5] = "3f";
            InverseSbox[7, 6] = "0f";
            InverseSbox[7, 7] = "02";
            InverseSbox[7, 8] = "c1";
            InverseSbox[7, 9] = "af";
            InverseSbox[7, 10] = "bd";
            InverseSbox[7, 11] = "03";
            InverseSbox[7, 12] = "01";
            InverseSbox[7, 13] = "13";
            InverseSbox[7, 14] = "8a";
            InverseSbox[7, 15] = "6b";

            InverseSbox[8, 0] = "3a";
            InverseSbox[8, 1] = "91";
            InverseSbox[8, 2] = "11";
            InverseSbox[8, 3] = "41";
            InverseSbox[8, 4] = "4f";
            InverseSbox[8, 5] = "67";
            InverseSbox[8, 6] = "dc";
            InverseSbox[8, 7] = "ea";
            InverseSbox[8, 8] = "97";
            InverseSbox[8, 9] = "f2";
            InverseSbox[8, 10] = "cf";
            InverseSbox[8, 11] = "ce";
            InverseSbox[8, 12] = "f0";
            InverseSbox[8, 13] = "b4";
            InverseSbox[8, 14] = "e6";
            InverseSbox[8, 15] = "73";

            InverseSbox[9, 0] = "96";
            InverseSbox[9, 1] = "ac";
            InverseSbox[9, 2] = "74";
            InverseSbox[9, 3] = "22";
            InverseSbox[9, 4] = "e7";
            InverseSbox[9, 5] = "ad";
            InverseSbox[9, 6] = "35";
            InverseSbox[9, 7] = "85";
            InverseSbox[9, 8] = "e2";
            InverseSbox[9, 9] = "f9";
            InverseSbox[9, 10] = "37";
            InverseSbox[9, 11] = "e8";
            InverseSbox[9, 12] = "1c";
            InverseSbox[9, 13] = "75";
            InverseSbox[9, 14] = "df";
            InverseSbox[9, 15] = "6e";

            InverseSbox[10, 0] = "47";
            InverseSbox[10, 1] = "f1";
            InverseSbox[10, 2] = "1a";
            InverseSbox[10, 3] = "71";
            InverseSbox[10, 4] = "1d";
            InverseSbox[10, 5] = "29";
            InverseSbox[10, 6] = "c5";
            InverseSbox[10, 7] = "89";
            InverseSbox[10, 8] = "6f";
            InverseSbox[10, 9] = "b7";
            InverseSbox[10, 10] = "62";
            InverseSbox[10, 11] = "0e";
            InverseSbox[10, 12] = "aa";
            InverseSbox[10, 13] = "18";
            InverseSbox[10, 14] = "be";
            InverseSbox[10, 15] = "1b";

            InverseSbox[11, 0] = "fc";
            InverseSbox[11, 1] = "56";
            InverseSbox[11, 2] = "3e";
            InverseSbox[11, 3] = "4b";
            InverseSbox[11, 4] = "c6";
            InverseSbox[11, 5] = "d2";
            InverseSbox[11, 6] = "79";
            InverseSbox[11, 7] = "20";
            InverseSbox[11, 8] = "9a";
            InverseSbox[11, 9] = "db";
            InverseSbox[11, 10] = "c0";
            InverseSbox[11, 11] = "fe";
            InverseSbox[11, 12] = "78";
            InverseSbox[11, 13] = "cd";
            InverseSbox[11, 14] = "5a";
            InverseSbox[11, 15] = "f4";

            InverseSbox[12, 0] = "1f";
            InverseSbox[12, 1] = "dd";
            InverseSbox[12, 2] = "a8";
            InverseSbox[12, 3] = "33";
            InverseSbox[12, 4] = "88";
            InverseSbox[12, 5] = "07";
            InverseSbox[12, 6] = "c7";
            InverseSbox[12, 7] = "31";
            InverseSbox[12, 8] = "b1";
            InverseSbox[12, 9] = "12";
            InverseSbox[12, 10] = "10";
            InverseSbox[12, 11] = "59";
            InverseSbox[12, 12] = "27";
            InverseSbox[12, 13] = "80";
            InverseSbox[12, 14] = "ec";
            InverseSbox[12, 15] = "5f";

            InverseSbox[13, 0] = "60";
            InverseSbox[13, 1] = "51";
            InverseSbox[13, 2] = "7f";
            InverseSbox[13, 3] = "a9";
            InverseSbox[13, 4] = "19";
            InverseSbox[13, 5] = "b5";
            InverseSbox[13, 6] = "4a";
            InverseSbox[13, 7] = "0d";
            InverseSbox[13, 8] = "2d";
            InverseSbox[13, 9] = "e5";
            InverseSbox[13, 10] = "7a";
            InverseSbox[13, 11] = "9f";
            InverseSbox[13, 12] = "93";
            InverseSbox[13, 13] = "c9";
            InverseSbox[13, 14] = "9c";
            InverseSbox[13, 15] = "ef";

            InverseSbox[14, 0] = "a0";
            InverseSbox[14, 1] = "e0";
            InverseSbox[14, 2] = "3b";
            InverseSbox[14, 3] = "4d";
            InverseSbox[14, 4] = "ae";
            InverseSbox[14, 5] = "2a";
            InverseSbox[14, 6] = "f5";
            InverseSbox[14, 7] = "b0";
            InverseSbox[14, 8] = "c8";
            InverseSbox[14, 9] = "eb";
            InverseSbox[14, 10] = "bb";
            InverseSbox[14, 11] = "3c";
            InverseSbox[14, 12] = "83";
            InverseSbox[14, 13] = "53";
            InverseSbox[14, 14] = "99";
            InverseSbox[14, 15] = "61";

            InverseSbox[15, 0] = "17";
            InverseSbox[15, 1] = "2b";
            InverseSbox[15, 2] = "04";
            InverseSbox[15, 3] = "7e";
            InverseSbox[15, 4] = "ba";
            InverseSbox[15, 5] = "77";
            InverseSbox[15, 6] = "d6";
            InverseSbox[15, 7] = "26";
            InverseSbox[15, 8] = "e1";
            InverseSbox[15, 9] = "69";
            InverseSbox[15, 10] = "14";
            InverseSbox[15, 11] = "63";
            InverseSbox[15, 12] = "55";
            InverseSbox[15, 13] = "21";
            InverseSbox[15, 14] = "0c";
            InverseSbox[15, 15] = "7d";

            #endregion
            //MixColumns
            #region InverseMiXColumns

            //rows
            InverseMixColumnsMatrix[0, 0] = "0E";
            InverseMixColumnsMatrix[0, 1] = "0B";
            InverseMixColumnsMatrix[0, 2] = "0D";
            InverseMixColumnsMatrix[0, 3] = "09";

            InverseMixColumnsMatrix[1, 0] = "09";
            InverseMixColumnsMatrix[1, 1] = "0E";
            InverseMixColumnsMatrix[1, 2] = "0B";
            InverseMixColumnsMatrix[1, 3] = "0D";

            InverseMixColumnsMatrix[2, 0] = "0D";
            InverseMixColumnsMatrix[2, 1] = "09";
            InverseMixColumnsMatrix[2, 2] = "0E";
            InverseMixColumnsMatrix[2, 3] = "0B";

            InverseMixColumnsMatrix[3, 0] = "0B";
            InverseMixColumnsMatrix[3, 1] = "0D";
            InverseMixColumnsMatrix[3, 2] = "09";
            InverseMixColumnsMatrix[3, 3] = "0E";

            #endregion
            //Rconstant
            #region Rconstant

            RConstant[0, 0] = "00000001";
            RConstant[0, 1] = "00000010";
            RConstant[0, 2] = "00000100";
            RConstant[0, 3] = "00001000";
            RConstant[0, 4] = "00010000";
            RConstant[0, 5] = "00100000";
            RConstant[0, 6] = "01000000";
            RConstant[0, 7] = "10000000";
            RConstant[0, 8] = "00011011";
            RConstant[0, 9] = "00110110";

            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 10; j++)
                {
                    RConstant[i, j] = "00000000";
                }
            }

            #endregion
            string binaryCipher = "";
            convertToBin(cipher,ref binaryCipher);
            string binarykey = "";
            convertToBin(mainKey,ref binarykey);
            string[,] RoundKeyMatrix = new string[4, 44];
            int binaryKeyCounter = 0;
            string ShiftRow;
            string[] ShiftColumn = new string[4];
            string[,] SpecificRoundKey = new string[4, 4];
            int KeyCount = 40;
            string[,] binarykeyMatrix = new string[4, 4];
            string[,] ResultRoundKeyMatrix = new string[4, 4];
            string[] LastColumnKey = new string[4];
            string[,] XorResultHexaMatrix = new string[4, 4];
            string[,] MixColumnsBinary = new string[4, 4];
            string[,] Sub_ByteSBoxResult = new string[4, 4];
            string[,] SBoxBinary = new string[4, 4];
            string[,] MixColumnsMatrixResult = new string[4, 4];
            string[,] MultipliOfMixColAndShiftRowMat = new string[4, 4];
            string[] MultiRowMixCol_ColShiftRow = new string[4];
            int MixColumnsMatrixResultCounter = 0;
            int counter = 0;
            string XorResultBinary = "";
            int XorResultHexaCounter = 0;
            int RCcounter = 0;
            string oneBitLastCol = "";
            string BinaryLastCol = "";
            string ConvertSBoxToBinarySTR;
            string ConvertMixColumnsToBinary;

            string multiplicationTemp1;

            string multiplicationTemp2;
            string multiplicationTemp3;

            string multiplicationTemp4;

            string oneB = "00011011";
            char X;
            int BinaryCipherCounter = 0;
            string ConBinaryTOHixa = "";
            StringBuilder XorResultHexa;
            int mod4Len;
            #region Key Generation

            //Store Binary Key In Matrix
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    RoundKeyMatrix[j, i] = binarykey.Substring(binaryKeyCounter, 8);
                    binaryKeyCounter += 8;
                }
            }



            //Fill Add RoundKey Matrix Start From Column 4
            //Columns
            for (int j = 4; j < 44; j++)
            {
                if (j % 4 == 0)
                {
                    //OneShift Sbox XOR RC Wj-1 
                    #region OneShift,Sbox,XOR RC XOR Wj-4 "W4 ,W8 ..."...

                    //1)..Column 3 .. one shift

                    ShiftRow = RoundKeyMatrix[0, j - 1];
                    for (int k = 0; k < 3; k++)
                    {
                        ShiftColumn[k] = RoundKeyMatrix[k + 1, j - 1];//
                    }
                    ShiftColumn[3] = ShiftRow;


                    //Convert LastColumn from binary to hexa
                    //Support:: Why 8 ?!
                    for (int k = 0; k < 4; k++)
                    {
                        StringBuilder LastColumnKeyHexa = new StringBuilder(ShiftColumn[k].Length / 8 + 1);
                        int mood4Len = ShiftColumn[k].Length % 8;
                        if (mood4Len != 0)
                        {
                            // pad to length multiple of 8
                            ShiftColumn[k] = ShiftColumn[k].PadLeft(((ShiftColumn[k].Length / 8) + 1) * 8, '0');
                        }
                        for (int i = 0; i < ShiftColumn[k].Length; i += 8)
                        {
                            string eightBits = ShiftColumn[k].Substring(i, 8);
                            LastColumnKeyHexa.AppendFormat("{0:X2}", Convert.ToByte(eightBits, 2));
                        }
                        ShiftColumn[k] = LastColumnKeyHexa.ToString();
                    }

                  
                    //2)..S-Box
                    #region s-box

                    for (int i = 0; i < 4; i++)
                    {
                        string temp = ShiftColumn[i];

                        int row = 0;
                        int column = 0;

                        //Check if row = hexa !!
                        if ((temp[0].ToString()) == "A")
                        {
                            row = 10;
                        }
                        else if ((temp[0].ToString()) == "B")
                        {
                            row = 11;
                        }
                        else if ((temp[0].ToString()) == "C")
                        {
                            row = 12;
                        }
                        else if ((temp[0].ToString()) == "D")
                        {
                            row = 13;
                        }
                        else if ((temp[0].ToString()) == "E")
                        {
                            row = 14;
                        }
                        else if ((temp[0].ToString()) == "F")
                        {
                            row = 15;
                        }
                        else
                        {
                            row = (int)Char.GetNumericValue(temp[0]);
                        }

                        //Check if column = hexa !!
                        if ((temp[1].ToString()) == "A")
                        {
                            column = 10;
                        }
                        else if ((temp[1].ToString()) == "B")
                        {
                            column = 11;
                        }
                        else if ((temp[1].ToString()) == "C")
                        {
                            column = 12;
                        }
                        else if ((temp[1].ToString()) == "D")
                        {
                            column = 13;
                        }
                        else if ((temp[1].ToString()) == "E")
                        {
                            column = 14;
                        }
                        else if ((temp[1].ToString()) == "F")
                        {
                            column = 15;
                        }
                        else
                        {
                            column = (int)Char.GetNumericValue(temp[1]);
                        }

                        ShiftColumn[i] = Sbox[row, column];
                    }

                    //print last column aftr s-box
                    //for (int i = 0; i < 4; i++)
                    //{
                    //    Console.WriteLine(ShiftColumn[i]);
                    //}

                    #endregion

                    //Convert Last Column Hexa To Binary
                    for (int i = 0; i < 4; i++)
                    {
                        foreach (char c in ShiftColumn[i])
                        {
                            oneBitLastCol = Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2);
                            while (oneBitLastCol.Length < 4)
                            {
                                oneBitLastCol = "0" + oneBitLastCol;
                            }
                            BinaryLastCol += oneBitLastCol;
                        }
                        ShiftColumn[i] = BinaryLastCol;
                        // Console.WriteLine(ShiftColumn[i]);

                        BinaryLastCol = "";
                    }

                    //3)..XOR RC BinaryLastCol
                    XorResultBinary = "";
                    for (int i = 0; i < 4; i++)
                    {
                        XorResultBinary = "";
                        for (int k = 0; k < 8; k++)
                        {

                            if (RConstant[i, RCcounter][k] == RoundKeyMatrix[i, j - 4][k])
                            {
                                X = '0';
                            }
                            else
                            {
                                X = '1';
                            }
                            if (ShiftColumn[i][k] == X)
                            {
                                X = '0';
                            }
                            else
                            {
                                X = '1';
                            }
                            XorResultBinary += X;
                        }
                        RoundKeyMatrix[i, j] = XorResultBinary;

                    }
                    RCcounter++;
                    #endregion
                }
                else
                {
                    XorResultBinary = "";
                    for (int i = 0; i < 4; i++)
                    {
                        XorResultBinary = "";
                        for (int k = 0; k < 8; k++)
                        {
                            if (RoundKeyMatrix[i, j - 1][k] == RoundKeyMatrix[i, j - 4][k])
                            {
                                XorResultBinary += "0";
                            }
                            else
                            {
                                XorResultBinary += "1";
                            }
                        }
                        RoundKeyMatrix[i, j] = XorResultBinary;
                    }

                }
            }

            #endregion
            //Add Round Key Step
            #region Add Round Key C.T XOR Key
            XorResultBinary = "";
            //Get The Last Key 
            for (int j = 40; j < 44; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    //Xor BinaryCipher & BinaryKey
                    for (int k = 0; k < 8; k++)
                    {
                        if (binaryCipher[BinaryCipherCounter] == RoundKeyMatrix[i, j][k])
                        {
                            XorResultBinary += "0";
                        }
                        else
                        {
                            XorResultBinary += "1";
                        }
                        if (BinaryCipherCounter < 128)
                        {
                            BinaryCipherCounter++;
                        }
                    }


                }
            }
            // Console.WriteLine(XorResultBinary);
            //Console.WriteLine();

            //Convert XorResult from binary to hexa
            //Support:: Why 8 ?!
            XorResultHexa = new StringBuilder(XorResultBinary.Length / 8 + 1);
            mod4Len = XorResultBinary.Length % 8;
            if (mod4Len != 0)
            {
                // pad to length multiple of 8
                XorResultBinary = XorResultBinary.PadLeft(((XorResultBinary.Length / 8) + 1) * 8, '0');
            }
            for (int i = 0; i < XorResultBinary.Length; i += 8)
            {
                string eightBits = XorResultBinary.Substring(i, 8);
                XorResultHexa.AppendFormat("{0:X2}", Convert.ToByte(eightBits, 2));
            }
            //Console.WriteLine(XorResultHexa.ToString());

            //Put XorResultHexa into matrix 4*4 
            //Column by Column
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    XorResultHexaMatrix[j, i] = XorResultHexa[XorResultHexaCounter].ToString();
                    XorResultHexaCounter++;
                    XorResultHexaMatrix[j, i] += XorResultHexa[XorResultHexaCounter].ToString();
                    XorResultHexaCounter++;
                }
            }




            #endregion
            //10 Iteration
            for (int p = 0; p < 10; p++)
            {
                #region Step 1 : ShiftRows
                //Row Zero NoShift

                //Row 1 .. one shift
                for (int j = 3; j > 0; j--)
                {

                    ShiftRow = XorResultHexaMatrix[1, j];
                    XorResultHexaMatrix[1, j] = XorResultHexaMatrix[1, j - 1];
                    XorResultHexaMatrix[1, j - 1] = ShiftRow;
                }



                //Row 2 ... two shifts

                //The First Shift
                for (int j = 3; j > 0; j--)
                {
                    ShiftRow = XorResultHexaMatrix[2, j];
                    XorResultHexaMatrix[2, j] = XorResultHexaMatrix[2, j - 1];
                    XorResultHexaMatrix[2, j - 1] = ShiftRow;
                }

                //The Second Shift
                for (int j = 3; j > 0; j--)
                {
                    ShiftRow = XorResultHexaMatrix[2, j];
                    XorResultHexaMatrix[2, j] = XorResultHexaMatrix[2, j - 1];
                    XorResultHexaMatrix[2, j - 1] = ShiftRow;
                }
                //Row 3 ..Three Shifts

                //The First Shift
                for (int j = 3; j > 0; j--)
                {
                    ShiftRow = XorResultHexaMatrix[3, j];
                    XorResultHexaMatrix[3, j] = XorResultHexaMatrix[3, j - 1];
                    XorResultHexaMatrix[3, j - 1] = ShiftRow;
                }

                //The Second Shift
                for (int j = 3; j > 0; j--)
                {
                    ShiftRow = XorResultHexaMatrix[3, j];
                    XorResultHexaMatrix[3, j] = XorResultHexaMatrix[3, j - 1];
                    XorResultHexaMatrix[3, j - 1] = ShiftRow;
                }

                //The Third Shift
                for (int j = 3; j > 0; j--)
                {
                    ShiftRow = XorResultHexaMatrix[3, j];
                    XorResultHexaMatrix[3, j] = XorResultHexaMatrix[3, j - 1];
                    XorResultHexaMatrix[3, j - 1] = ShiftRow;
                }


                #endregion
                //Step 2 : Sub-Byte"Sbox"
                #region Step 2 : Sub-Byte InverseSbox

                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        string temp = XorResultHexaMatrix[i, j];

                        int row = 0;
                        int column = 0;

                        //Check if row = hexa !!
                        if ((temp[0].ToString()) == "A")
                        {
                            row = 10;
                        }
                        else if ((temp[0].ToString()) == "B")
                        {
                            row = 11;
                        }
                        else if ((temp[0].ToString()) == "C")
                        {
                            row = 12;
                        }
                        else if ((temp[0].ToString()) == "D")
                        {
                            row = 13;
                        }
                        else if ((temp[0].ToString()) == "E")
                        {
                            row = 14;
                        }
                        else if ((temp[0].ToString()) == "F")
                        {
                            row = 15;
                        }
                        else
                        {
                            row = (int)Char.GetNumericValue(temp[0]);
                        }

                        //Check if column = hexa !!
                        if ((temp[1].ToString()) == "A")
                        {
                            column = 10;
                        }
                        else if ((temp[1].ToString()) == "B")
                        {
                            column = 11;
                        }
                        else if ((temp[1].ToString()) == "C")
                        {
                            column = 12;
                        }
                        else if ((temp[1].ToString()) == "D")
                        {
                            column = 13;
                        }
                        else if ((temp[1].ToString()) == "E")
                        {
                            column = 14;
                        }
                        else if ((temp[1].ToString()) == "F")
                        {
                            column = 15;
                        }
                        else
                        {
                            column = (int)Char.GetNumericValue(temp[1]);
                        }

                        Sub_ByteSBoxResult[i, j] = InverseSbox[row, column];
                    }
                }


                #endregion
                //Step 3 : Add RoundKey 1->9
                #region Add RoundKey

                //GetRoundKey Key1 At Round1 .. key2 At Round 2...
                KeyCount = KeyCount - 4;
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        SpecificRoundKey[i, j] = RoundKeyMatrix[i, KeyCount + j];

                    }
                }


                SBoxBinary = new string[4, 4];

                ConvertSBoxToBinarySTR = "";
                //Convert S-Box To Binary
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        ConvertSBoxToBinarySTR = "";
                        foreach (char c in Sub_ByteSBoxResult[i, j])
                        {
                            ConvertSBoxToBinarySTR = Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2);

                            while (ConvertSBoxToBinarySTR.Length < 4)
                            {
                                ConvertSBoxToBinarySTR = "0" + ConvertSBoxToBinarySTR;
                            }

                            SBoxBinary[i, j] += ConvertSBoxToBinarySTR;
                        }

                    }
                }

                XorResultBinary = "";
                //Xor Round Key N  & S-Box
                for (int k = 0; k < 4; k++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        XorResultBinary = "";
                        for (int t = 0; t < 8; t++)
                        {
                            if (SpecificRoundKey[k, i][t] == SBoxBinary[k, i][t])
                            {
                                XorResultBinary += "0";
                            }
                            else
                            {
                                XorResultBinary += "1";
                            }

                        }
                        ResultRoundKeyMatrix[k, i] = XorResultBinary;
                    }
                }

                #endregion
                if (p != 9)
                {
                    //Step 4 : Mix Columns
                    #region Step 4 : Multiplication Of MixColumns & AddRoundKey

                    //Convert MixColumns To Binary
                    MixColumnsBinary = new string[4, 4];
                    for (int i = 0; i < 4; i++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            ConvertMixColumnsToBinary = "";
                            foreach (char c in InverseMixColumnsMatrix[i, j])
                            {
                                ConvertMixColumnsToBinary = Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2);

                                while (ConvertMixColumnsToBinary.Length < 4)
                                {
                                    ConvertMixColumnsToBinary = "0" + ConvertMixColumnsToBinary;
                                }

                                MixColumnsBinary[i, j] += ConvertMixColumnsToBinary;
                            }

                        }
                    }


                    //We Have The Mix Columns Binary Matrix & Shift Rows Binary Matrix

                    //MixColumns & ShiftRows multiplication  
                    for (int i = 0; i < 4; i++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            for (int w = 0; w < 4; w++)
                            {
                                MixColumnsMatrixResult[i, j] = "";

                                //Check if mix columns = 09
                                if (MixColumnsBinary[i, w] == "00001001")
                                {
                                    #region Multiplication 09

                                    //first step -- same as 02

                                    //check if the most bit =1 
                                    multiplicationTemp1 = ResultRoundKeyMatrix[w, j];
                                    for (int n = 0; n < 3; n++)
                                    {
                                        if (multiplicationTemp1[0] == '1')
                                        {
                                            //shift
                                            multiplicationTemp1 = multiplicationTemp1.Substring(1, 7);
                                            multiplicationTemp1 += '0';

                                            XorResultBinary = "";
                                            //Xor 1b=x^4+x+1 !!Support & multiplicationTemp2
                                            for (int k = 0; k < multiplicationTemp1.Length; k++)
                                            {

                                                if (multiplicationTemp1[k] == oneB[k])
                                                {
                                                    XorResultBinary += "0";
                                                }
                                                else
                                                {
                                                    XorResultBinary += "1";
                                                }

                                            }
                                            multiplicationTemp1 = XorResultBinary;
                                        }
                                        //check if the most bit =0
                                        else
                                        {
                                            //shift
                                            multiplicationTemp1 = multiplicationTemp1.Substring(1, 7);
                                            multiplicationTemp1 += '0';

                                        }


                                    }


                                    //Second step Xor with itself

                                    XorResultBinary = "";
                                    string temp = ResultRoundKeyMatrix[w, j];

                                    //Xor 
                                    for (int k = 0; k < multiplicationTemp1.Length; k++)
                                    {
                                        if (multiplicationTemp1[k] == temp[k])
                                        {
                                            XorResultBinary += "0";
                                        }
                                        else
                                        {
                                            XorResultBinary += "1";
                                        }
                                    }
                                    multiplicationTemp1 = XorResultBinary;

                                    MultiRowMixCol_ColShiftRow[counter] = multiplicationTemp1;
                                    counter++;

                                    #endregion
                                }

                                //Check if mix columns = 0B
                                else if (MixColumnsBinary[i, w] == "00001011")
                                {
                                    //0B-> *2, *2 ,XOR with itself ,*2 XOr with itself
                                    #region 0B
                                    multiplicationTemp2 = ResultRoundKeyMatrix[w, j];

                                    //Multiply ResultRoundKeyMatrix[w, j] *2 ,*2
                                    for (int n = 0; n < 2; n++)
                                    {
                                        if (multiplicationTemp2[0] == '1')
                                        {
                                            //shift
                                            multiplicationTemp2 = multiplicationTemp2.Substring(1, 7);
                                            multiplicationTemp2 += '0';

                                            XorResultBinary = "";
                                            //Xor 1b=x^4+x+1 !!Support & multiplicationTemp2
                                            for (int k = 0; k < multiplicationTemp2.Length; k++)
                                            {

                                                if (multiplicationTemp2[k] == oneB[k])
                                                {
                                                    XorResultBinary += "0";
                                                }
                                                else
                                                {
                                                    XorResultBinary += "1";
                                                }

                                            }
                                            multiplicationTemp2 = XorResultBinary;
                                        }
                                        //check if the most bit =0
                                        else
                                        {
                                            //shift
                                            multiplicationTemp2 = multiplicationTemp2.Substring(1, 7);
                                            multiplicationTemp2 += '0';
                                        }
                                    }


                                    XorResultBinary = "";
                                    //Xor with itself 
                                    for (int k = 0; k < multiplicationTemp2.Length; k++)
                                    {
                                        string temp = ResultRoundKeyMatrix[w, j];
                                        if (multiplicationTemp2[k] == temp[k])
                                        {
                                            XorResultBinary += "0";
                                        }
                                        else
                                        {
                                            XorResultBinary += "1";
                                        }
                                    }
                                    multiplicationTemp2 = XorResultBinary;


                                    //Multiply *2
                                    if (multiplicationTemp2[0] == '1')
                                    {
                                        //shift
                                        multiplicationTemp2 = multiplicationTemp2.Substring(1, 7);
                                        multiplicationTemp2 += '0';

                                        XorResultBinary = "";
                                        //Xor 1b=x^4+x+1 !!Support & multiplicationTemp2
                                        for (int k = 0; k < multiplicationTemp2.Length; k++)
                                        {

                                            if (multiplicationTemp2[k] == oneB[k])
                                            {
                                                XorResultBinary += "0";
                                            }
                                            else
                                            {
                                                XorResultBinary += "1";
                                            }

                                        }
                                        multiplicationTemp2 = XorResultBinary;
                                    }
                                    //check if the most bit =0
                                    else
                                    {
                                        //shift
                                        multiplicationTemp2 = multiplicationTemp2.Substring(1, 7);
                                        multiplicationTemp2 += '0';
                                    }
                                    XorResultBinary = "";
                                    //XOR with it self
                                    for (int k = 0; k < multiplicationTemp2.Length; k++)
                                    {
                                        string temp = ResultRoundKeyMatrix[w, j];
                                        if (multiplicationTemp2[k] == temp[k])
                                        {
                                            XorResultBinary += "0";
                                        }
                                        else
                                        {
                                            XorResultBinary += "1";
                                        }
                                    }
                                    multiplicationTemp2 = XorResultBinary;

                                    MultiRowMixCol_ColShiftRow[counter] = multiplicationTemp2;

                                    counter++;
                                    #endregion
                                }

                                //Check if mix columns = 0E
                                else if (MixColumnsBinary[i, w] == "00001110")
                                {
                                    #region 0E
                                    
                                    //Multiplication 01
                                    multiplicationTemp4 = ResultRoundKeyMatrix[w, j];

                                    for (int n = 0; n < 2; n++)
                                    {
                                        if (multiplicationTemp4[0] == '1')
                                        {
                                            //shift
                                            multiplicationTemp4 = multiplicationTemp4.Substring(1, 7);
                                            multiplicationTemp4 += '0';

                                            XorResultBinary = "";
                                            //Xor 1b=x^4+x+1 !!Support & multiplicationTemp2
                                            for (int k = 0; k < multiplicationTemp4.Length; k++)
                                            {

                                                if (multiplicationTemp4[k] == oneB[k])
                                                {
                                                    XorResultBinary += "0";
                                                }
                                                else
                                                {
                                                    XorResultBinary += "1";
                                                }

                                            }
                                            multiplicationTemp4 = XorResultBinary;
                                        }
                                        //check if the most bit =0
                                        else
                                        {
                                            //shift
                                            multiplicationTemp4 = multiplicationTemp4.Substring(1, 7);
                                            multiplicationTemp4 += '0';
                                        }

                                        XorResultBinary = "";
                                        //Xor with itself 
                                        for (int k = 0; k < multiplicationTemp4.Length; k++)
                                        {
                                            string temp = ResultRoundKeyMatrix[w, j];
                                            if (multiplicationTemp4[k] == temp[k])
                                            {
                                                XorResultBinary += "0";
                                            }
                                            else
                                            {
                                                XorResultBinary += "1";
                                            }
                                        }
                                        multiplicationTemp4 = XorResultBinary;

                                    }

                                    if (multiplicationTemp4[0] == '1')
                                    {
                                        //shift
                                        multiplicationTemp4 = multiplicationTemp4.Substring(1, 7);
                                        multiplicationTemp4 += '0';

                                        XorResultBinary = "";
                                       
                                        for (int k = 0; k < multiplicationTemp4.Length; k++)
                                        {

                                            if (multiplicationTemp4[k] == oneB[k])
                                            {
                                                XorResultBinary += "0";
                                            }
                                            else
                                            {
                                                XorResultBinary += "1";
                                            }

                                        }
                                        multiplicationTemp4 = XorResultBinary;
                                    }
                                    //check if the most bit =0
                                    else
                                    {
                                        //shift
                                        multiplicationTemp4 = multiplicationTemp4.Substring(1, 7);
                                        multiplicationTemp4 += '0';
                                    }



                                    MultiRowMixCol_ColShiftRow[counter] = multiplicationTemp4;

                                    counter++;

                                    #endregion
                                }
                                //Check if mix columns = 0D
                                else
                                {

                                    #region 0D

                                    multiplicationTemp3 = ResultRoundKeyMatrix[w, j];

                                    if (multiplicationTemp3[0] == '1')
                                    {
                                        //shift
                                        multiplicationTemp3 = multiplicationTemp3.Substring(1, 7);
                                        multiplicationTemp3 += '0';

                                        XorResultBinary = "";
                                        //Xor 1b=x^4+x+1 !!Support & multiplicationTemp2
                                        for (int k = 0; k < multiplicationTemp3.Length; k++)
                                        {

                                            if (multiplicationTemp3[k] == oneB[k])
                                            {
                                                XorResultBinary += "0";
                                            }
                                            else
                                            {
                                                XorResultBinary += "1";
                                            }

                                        }
                                        multiplicationTemp3 = XorResultBinary;
                                    }
                                    //check if the most bit =0
                                    else
                                    {
                                        //shift
                                        multiplicationTemp3 = multiplicationTemp3.Substring(1, 7);
                                        multiplicationTemp3 += '0';
                                    }

                                    XorResultBinary = "";
                                    //Xor with itself 
                                    for (int k = 0; k < multiplicationTemp3.Length; k++)
                                    {
                                        string temp = ResultRoundKeyMatrix[w, j];
                                        if (multiplicationTemp3[k] == temp[k])
                                        {
                                            XorResultBinary += "0";
                                        }
                                        else
                                        {
                                            XorResultBinary += "1";
                                        }
                                    }
                                    multiplicationTemp3 = XorResultBinary;

                                    for (int n = 0; n < 2; n++)
                                    {
                                        if (multiplicationTemp3[0] == '1')
                                        {
                                            //shift
                                            multiplicationTemp3 = multiplicationTemp3.Substring(1, 7);
                                            multiplicationTemp3 += '0';

                                            XorResultBinary = "";
                                            //Xor 1b=x^4+x+1 !!Support & multiplicationTemp2
                                            for (int k = 0; k < multiplicationTemp3.Length; k++)
                                            {

                                                if (multiplicationTemp3[k] == oneB[k])
                                                {
                                                    XorResultBinary += "0";
                                                }
                                                else
                                                {
                                                    XorResultBinary += "1";
                                                }

                                            }
                                            multiplicationTemp3 = XorResultBinary;
                                        }
                                        //check if the most bit =0
                                        else
                                        {
                                            //shift
                                            multiplicationTemp3 = multiplicationTemp3.Substring(1, 7);
                                            multiplicationTemp3 += '0';
                                        }
                                    }

                                    XorResultBinary = "";
                                    //Xor with itself 
                                    for (int k = 0; k < multiplicationTemp3.Length; k++)
                                    {
                                        string temp = ResultRoundKeyMatrix[w, j];
                                        if (multiplicationTemp3[k] == temp[k])
                                        {
                                            XorResultBinary += "0";
                                        }
                                        else
                                        {
                                            XorResultBinary += "1";
                                        }
                                    }
                                    multiplicationTemp3 = XorResultBinary;

                                    MultiRowMixCol_ColShiftRow[counter] = multiplicationTemp3;

                                    counter++;
                                    #endregion

                                }

                                if (w == 3)
                                {
                                    //Xor The 4 result of multiply mixcolumn row wih shiftrow column
                                    XorResultBinary = "";
                                    for (int l = 0; l < 8; l++)
                                    {
                                        if ((MultiRowMixCol_ColShiftRow[0][l] == MultiRowMixCol_ColShiftRow[1][l]))
                                        {
                                            X = '0';
                                        }
                                        else
                                        {
                                            X = '1';

                                        }

                                        if (MultiRowMixCol_ColShiftRow[2][l] == X)
                                        {
                                            X = '0';
                                        }
                                        else
                                        {
                                            X = '1';
                                        }
                                        if (MultiRowMixCol_ColShiftRow[3][l] == X)
                                        {
                                            X = '0';
                                        }
                                        else
                                        {
                                            X = '1';
                                        }
                                        XorResultBinary += X;
                                    }

                                    //Result of MixColumnsRow * ShiftRowColumn
                                    MixColumnsMatrixResult[i, MixColumnsMatrixResultCounter] = XorResultBinary;

                                    MixColumnsMatrixResultCounter++;

                                    if (MixColumnsMatrixResultCounter == 4)
                                    {
                                        MixColumnsMatrixResultCounter = 0;
                                    }

                                }
                            }
                            counter = 0;
                        }

                    }



                    

                    //Store result in XorResultHexaMatrix
                    ConBinaryTOHixa = "";
                    for (int i = 0; i < 4; i++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            //XorResultHexaMatrix[i, j] = MixColumnsMatrixResult[i,j];
                            ConBinaryTOHixa += MixColumnsMatrixResult[i, j];
                        }
                    }

                    //Convert XorResult from binary to hexa
                    
                    XorResultHexa = new StringBuilder(ConBinaryTOHixa.Length / 8 + 1);
                    mod4Len = ConBinaryTOHixa.Length % 8;
                    if (mod4Len != 0)
                    {
                        // pad to length multiple of 8
                        ConBinaryTOHixa = ConBinaryTOHixa.PadLeft(((ConBinaryTOHixa.Length / 8) + 1) * 8, '0');
                    }
                    for (int i = 0; i < ConBinaryTOHixa.Length; i += 8)
                    {
                        string eightBits = ConBinaryTOHixa.Substring(i, 8);
                        XorResultHexa.AppendFormat("{0:X2}", Convert.ToByte(eightBits, 2));
                    }
                    int cccc = 0;
                    XorResultHexaMatrix = new string[4, 4];
                    for (int i = 0; i < 4; i++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            XorResultHexaMatrix[i, j] += XorResultHexa[cccc];
                            cccc++;
                            XorResultHexaMatrix[i, j] += XorResultHexa[cccc];
                            cccc++;
                        }
                    }

                    #endregion

                }
                else
                {

                    XorResultBinary = "";
                    for (int i = 0; i < 4; i++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            XorResultBinary += ResultRoundKeyMatrix[j, i];
                        }
                    }
                    //Convert XorResult from binary to hexa
                    
                    XorResultHexa = new StringBuilder(XorResultBinary.Length / 8 + 1);
                    mod4Len = XorResultBinary.Length % 8;
                    if (mod4Len != 0)
                    {
                        // pad to length multiple of 8
                        XorResultBinary = XorResultBinary.PadLeft(((XorResultBinary.Length / 8) + 1) * 8, '0');
                    }
                    for (int i = 0; i < XorResultBinary.Length; i += 8)
                    {
                        string eightBits = XorResultBinary.Substring(i, 8);
                        XorResultHexa.AppendFormat("{0:X2}", Convert.ToByte(eightBits, 2));
                    }

                }


            }
            for (int i = 0; i < XorResultHexa.Length; i++)
            {
                mainPlain += XorResultHexa[i];
            }
            return mainPlain;

        }  
        public override string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            string mainPlain = "", mainKey = "";
            string mainCipher = "0x";
            for (int i = 2; i < plainText.Length; i++)
            {
                mainPlain += plainText[i];
            }
            for (int i = 2; i < plainText.Length; i++)
            {
                mainKey += key[i];
            }
            char X; int KeyCount = 4;
            string[,] Sbox = new string[16, 16];
            FillSBox(ref Sbox);
            #region RC
            string[,] RConstant = new string[4, 10];
            RConstant[0, 0] = "00000001";
            RConstant[0, 1] = "00000010";
            RConstant[0, 2] = "00000100";
            RConstant[0, 3] = "00001000";
            RConstant[0, 4] = "00010000";
            RConstant[0, 5] = "00100000";
            RConstant[0, 6] = "01000000";
            RConstant[0, 7] = "10000000";
            RConstant[0, 8] = "00011011";
            RConstant[0, 9] = "00110110";
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 10; j++)
                {
                    RConstant[i, j] = "00000000";
                }
            }
            #endregion
            string binaryPlain = "";
            convertToBin(mainPlain, ref binaryPlain);
            // Console.WriteLine(binaryPlain);
            string binaryKey = "";
            convertToBin(mainKey, ref binaryKey);
            string ResultBinary = "";
            for (int i = 0; i < binaryPlain.Length; i++)
            {
                if (binaryPlain[i] == binaryKey[i])
                {
                    ResultBinary += "0";
                }
                else
                {
                    ResultBinary += "1";
                }
            }
            StringBuilder ResultHexa = new StringBuilder(ResultBinary.Length / 8 + 1);
            int modLen = ResultBinary.Length % 8;
            if (modLen != 0)
            {
                // pad to length multiple of 8
                ResultBinary = ResultBinary.PadLeft(((ResultBinary.Length / 8) + 1) * 8, '0');
            }
            for (int i = 0; i < ResultBinary.Length; i += 8)
            {
                string eightBits = ResultBinary.Substring(i, 8);
                ResultHexa.AppendFormat("{0:X2}", Convert.ToByte(eightBits, 2));
            }
            // convert result to matrix
            string[,] XorResultHexaMatrix = new string[4, 4];
            int c = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    XorResultHexaMatrix[j, i] = ResultHexa[c].ToString();
                    XorResultHexaMatrix[j, i] += ResultHexa[c + 1].ToString();
                    c += 2;
                }
            }
            string[,] RoundKeyMatrix = new string[4, 44];
            int KeyCounter = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    RoundKeyMatrix[j, i] = binaryKey.Substring(KeyCounter, 8);
                    KeyCounter += 8;
                }
            }
            int RCcounter = 0;
            #region key schedule
            for (int j = 4; j < 44; j++)
            {
                if (j % 4 == 0)
                {
                    // rot Word
                    string[] shiftCol = new string[4];
                    shiftCol[0] = RoundKeyMatrix[1, j - 1];
                    shiftCol[1] = RoundKeyMatrix[2, j - 1];
                    shiftCol[2] = RoundKeyMatrix[3, j - 1];
                    shiftCol[3] = RoundKeyMatrix[0, j - 1];
                    for (int k = 0; k < 4; k++)
                    {
                        StringBuilder LastColumnKeyHexa = new StringBuilder(shiftCol[k].Length / 8 + 1);
                        int modLen2 = shiftCol[k].Length % 8;
                        if (modLen2 != 0)
                        {
                            // pad to length multiple of 8
                            shiftCol[k] = shiftCol[k].PadLeft(((shiftCol[k].Length / 8) + 1) * 8, '0');
                        }
                        for (int i = 0; i < shiftCol[k].Length; i += 8)
                        {
                            string eightBits = shiftCol[k].Substring(i, 8);
                            LastColumnKeyHexa.AppendFormat("{0:X2}", Convert.ToByte(eightBits, 2));
                        }
                        shiftCol[k] = LastColumnKeyHexa.ToString();
                    }

                    string[] sbytes = new string[4];
                    subByte1DArray(shiftCol, Sbox, ref sbytes);
                    string oneBitLastCol, BinaryLastCol = "";

                    //convert last column to binary
                    for (int i = 0; i < 4; i++)
                    {
                        foreach (char ch in sbytes[i])
                        {
                            oneBitLastCol = Convert.ToString(Convert.ToInt32(ch.ToString(), 16), 2);
                            while (oneBitLastCol.Length < 4)
                            {
                                oneBitLastCol = "0" + oneBitLastCol;
                            }
                            BinaryLastCol += oneBitLastCol;
                        }
                        sbytes[i] = BinaryLastCol;

                        BinaryLastCol = "";
                    }

                    // XOR RConstant matrix with last column
                    ResultBinary = "";

                    for (int i = 0; i < 4; i++)
                    {
                        ResultBinary = "";
                        for (int k = 0; k < 8; k++)
                        {

                            if (sbytes[i][k] == RoundKeyMatrix[i, j - 4][k])
                            {
                                X = '0';
                            }
                            else
                            {
                                X = '1';
                            }

                            if (RConstant[i, RCcounter][k] == X)
                            {
                                X = '0';
                            }
                            else
                            {
                                X = '1';
                            }
                            ResultBinary += X;
                        }
                        RoundKeyMatrix[i, j] = ResultBinary;

                    }

                    RCcounter++;
                }
                else
                {
                    ResultBinary = "";
                    for (int i = 0; i < 4; i++)
                    {
                        ResultBinary = "";
                        for (int k = 0; k < 8; k++)
                        {
                            if (RoundKeyMatrix[i, j - 1][k] == RoundKeyMatrix[i, j - 4][k])
                            {
                                ResultBinary += "0";
                            }
                            else
                            {
                                ResultBinary += "1";
                            }
                        }
                        RoundKeyMatrix[i, j] = ResultBinary;

                    }

                }

            }


            #endregion
            string[,] MixColsMat = new string[4, 4];
            #region Mix_C_Mat
            MixColsMat[0, 0] = "00000010";
            MixColsMat[0, 1] = "00000011";
            MixColsMat[0, 2] = "00000001";
            MixColsMat[0, 3] = "00000001";

            MixColsMat[1, 0] = "00000001";
            MixColsMat[1, 1] = "00000010";
            MixColsMat[1, 2] = "00000011";
            MixColsMat[1, 3] = "00000001";

            MixColsMat[2, 0] = "00000001";
            MixColsMat[2, 1] = "00000001";
            MixColsMat[2, 2] = "00000010";
            MixColsMat[2, 3] = "00000011";

            MixColsMat[3, 0] = "00000011";
            MixColsMat[3, 1] = "00000001";
            MixColsMat[3, 2] = "00000001";
            MixColsMat[3, 3] = "00000010";
            #endregion
            for (int it = 0; it < 10; it++)
            {

                // STEP 1 ( getting Sub Byte matrix)
                string[,] sByte = new string[4, 4];
                subByte(XorResultHexaMatrix, Sbox, ref sByte);
                // STEP 2 Shift Rows
                string[,] shiftRowMat = new string[4, 4];
                shiftRows(sByte, ref shiftRowMat);
                string[,] shiftRowsBin = new string[4, 4];
                //Convert ShiftRows To Binary
                convertToBin2(shiftRowMat, ref shiftRowsBin);

                string[,] MixColumnsResult = new string[4, 4];
                if (it < 9)
                {
                    //STEP 3 Mix Columns [for 9 iterations only]
                    MixColumns(MixColsMat, shiftRowsBin, ref MixColumnsResult);
                    //STEP 4 Add Round Key
                    string[,] SpecificRoundKey = new string[4, 4];

                    for (int i = 0; i < 4; i++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            SpecificRoundKey[i, j] = RoundKeyMatrix[i, KeyCount + j];

                        }
                    }
                    KeyCount += 4;
                    ResultBinary = "";
                    for (int ki = 0; ki < 4; ki++)
                    {
                        for (int i = 0; i < 4; i++)
                        {

                            for (int t = 0; t < 8; t++)
                            {
                                if (SpecificRoundKey[ki, i][t] == MixColumnsResult[ki, i][t])
                                {
                                    ResultBinary += "0";
                                }
                                else
                                {
                                    ResultBinary += "1";
                                }

                            }
                        }
                    }
                    ResultHexa = new StringBuilder(ResultBinary.Length / 8 + 1);
                    modLen = ResultBinary.Length % 8;
                    if (modLen != 0)
                    {
                        // pad to length multiple of 8
                        ResultBinary = ResultBinary.PadLeft(((ResultBinary.Length / 8) + 1) * 8, '0');
                    }
                    for (int i = 0; i < ResultBinary.Length; i += 8)
                    {
                        string eightBits = ResultBinary.Substring(i, 8);
                        ResultHexa.AppendFormat("{0:X2}", Convert.ToByte(eightBits, 2));
                    }
                    //Put XorResultHexa into matrix 4*4 
                    c = 0;
                    for (int i = 0; i < 4; i++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            XorResultHexaMatrix[i, j] = ResultHexa[c].ToString();
                            XorResultHexaMatrix[i, j] += ResultHexa[c + 1].ToString();
                            c += 2;
                        }
                    }


                }
                //  for Iteration 10
                else
                {
                    // STEP 4 (Add round Key)
                    string[,] SpecificRoundKey = new string[4, 4];
                    for (int i = 0; i < 4; i++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            SpecificRoundKey[i, j] = RoundKeyMatrix[i, KeyCount + j];

                        }
                    }
                    KeyCount += 4;
                    ResultBinary = "";
                    for (int k = 0; k < 4; k++)
                    {
                        for (int i = 0; i < 4; i++)
                        {

                            for (int t = 0; t < 8; t++)
                            {
                                if (SpecificRoundKey[k, i][t] == shiftRowsBin[k, i][t])
                                {
                                    ResultBinary += "0";
                                }
                                else
                                {
                                    ResultBinary += "1";
                                }

                            }
                        }
                    }
                    ResultHexa = new StringBuilder(ResultBinary.Length / 8 + 1);
                    modLen = ResultBinary.Length % 8;
                    if (modLen != 0)
                    {
                        // pad to length multiple of 8
                        ResultBinary = ResultBinary.PadLeft(((ResultBinary.Length / 8) + 1) * 8, '0');
                    }
                    for (int i = 0; i < ResultBinary.Length; i += 8)
                    {
                        string eightBits = ResultBinary.Substring(i, 8);
                        ResultHexa.AppendFormat("{0:X2}", Convert.ToByte(eightBits, 2));
                    }
                     c = 0;
                    //Put XorResultHexa into matrix 4*4 
                    for (int i = 0; i < 4; i++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            XorResultHexaMatrix[i, j] = ResultHexa[c].ToString();
                            XorResultHexaMatrix[i, j] += ResultHexa[c + 1].ToString();
                            c += 2;
                        }
                    }

                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    mainCipher += XorResultHexaMatrix[j, i];
                }
            }
            Console.WriteLine(mainCipher);
            return mainCipher;
        }
        public void FillSBox(ref string[,] arr)
        {
            arr[0, 0] = "63";
            arr[0, 1] = "7c";
            arr[0, 2] = "77";
            arr[0, 3] = "7b";
            arr[0, 4] = "f2";
            arr[0, 5] = "6b";
            arr[0, 6] = "6f";
            arr[0, 7] = "c5";
            arr[0, 8] = "30";
            arr[0, 9] = "01";
            arr[0, 10] = "67";
            arr[0, 11] = "2b";
            arr[0, 12] = "fe";
            arr[0, 13] = "d7";
            arr[0, 14] = "ab";
            arr[0, 15] = "76";

            arr[1, 0] = "ca";
            arr[1, 1] = "82";
            arr[1, 2] = "c9";
            arr[1, 3] = "7d";
            arr[1, 4] = "fa";
            arr[1, 5] = "59";
            arr[1, 6] = "47";
            arr[1, 7] = "f0";
            arr[1, 8] = "ad";
            arr[1, 9] = "d4";
            arr[1, 10] = "a2";
            arr[1, 11] = "af";
            arr[1, 12] = "9c";
            arr[1, 13] = "a4";
            arr[1, 14] = "72";
            arr[1, 15] = "c0";

            arr[2, 0] = "b7";
            arr[2, 1] = "fd";
            arr[2, 2] = "93";
            arr[2, 3] = "26";
            arr[2, 4] = "36";
            arr[2, 5] = "3f";
            arr[2, 6] = "f7";
            arr[2, 7] = "cc";
            arr[2, 8] = "34";
            arr[2, 9] = "a5";
            arr[2, 10] = "e5";
            arr[2, 11] = "f1";
            arr[2, 12] = "71";
            arr[2, 13] = "d8";
            arr[2, 14] = "31";
            arr[2, 15] = "15";

            arr[3, 0] = "04";
            arr[3, 1] = "c7";
            arr[3, 2] = "23";
            arr[3, 3] = "c3";
            arr[3, 4] = "18";
            arr[3, 5] = "96";
            arr[3, 6] = "05";
            arr[3, 7] = "9a";
            arr[3, 8] = "07";
            arr[3, 9] = "12";
            arr[3, 10] = "80";
            arr[3, 11] = "e2";
            arr[3, 12] = "eb";
            arr[3, 13] = "27";
            arr[3, 14] = "b2";
            arr[3, 15] = "75";

            arr[4, 0] = "09";
            arr[4, 1] = "83";
            arr[4, 2] = "2c";
            arr[4, 3] = "1a";
            arr[4, 4] = "1b";
            arr[4, 5] = "6e";
            arr[4, 6] = "5a";
            arr[4, 7] = "a0";
            arr[4, 8] = "52";
            arr[4, 9] = "3b";
            arr[4, 10] = "d6";
            arr[4, 11] = "b3";
            arr[4, 12] = "29";
            arr[4, 13] = "e3";
            arr[4, 14] = "2f";
            arr[4, 15] = "84";

            arr[5, 0] = "53";
            arr[5, 1] = "d1";
            arr[5, 2] = "00";
            arr[5, 3] = "ed";
            arr[5, 4] = "20";
            arr[5, 5] = "fc";
            arr[5, 6] = "b1";
            arr[5, 7] = "5b";
            arr[5, 8] = "6a";
            arr[5, 9] = "cb";
            arr[5, 10] = "be";
            arr[5, 11] = "39";
            arr[5, 12] = "4a";
            arr[5, 13] = "4c";
            arr[5, 14] = "58";
            arr[5, 15] = "cf";

            arr[6, 0] = "d0";
            arr[6, 1] = "ef";
            arr[6, 2] = "aa";
            arr[6, 3] = "fb";
            arr[6, 4] = "43";
            arr[6, 5] = "4d";
            arr[6, 6] = "33";
            arr[6, 7] = "85";
            arr[6, 8] = "45";
            arr[6, 9] = "f9";
            arr[6, 10] = "02";
            arr[6, 11] = "7f";
            arr[6, 12] = "50";
            arr[6, 13] = "3c";
            arr[6, 14] = "9f";
            arr[6, 15] = "a8";

            arr[7, 0] = "51";
            arr[7, 1] = "a3";
            arr[7, 2] = "40";
            arr[7, 3] = "8f";
            arr[7, 4] = "92";
            arr[7, 5] = "9d";
            arr[7, 6] = "38";
            arr[7, 7] = "f5";
            arr[7, 8] = "bc";
            arr[7, 9] = "b6";
            arr[7, 10] = "da";
            arr[7, 11] = "21";
            arr[7, 12] = "10";
            arr[7, 13] = "ff";
            arr[7, 14] = "f3";
            arr[7, 15] = "d2";

            arr[8, 0] = "cd";
            arr[8, 1] = "0c";
            arr[8, 2] = "13";
            arr[8, 3] = "ec";
            arr[8, 4] = "5f";
            arr[8, 5] = "97";
            arr[8, 6] = "44";
            arr[8, 7] = "17";
            arr[8, 8] = "c4";
            arr[8, 9] = "a7";
            arr[8, 10] = "7e";
            arr[8, 11] = "3d";
            arr[8, 12] = "64";
            arr[8, 13] = "5d";
            arr[8, 14] = "19";
            arr[8, 15] = "73";

            arr[9, 0] = "60";
            arr[9, 1] = "81";
            arr[9, 2] = "4f";
            arr[9, 3] = "dc";
            arr[9, 4] = "22";
            arr[9, 5] = "2a";
            arr[9, 6] = "90";
            arr[9, 7] = "88";
            arr[9, 8] = "46";
            arr[9, 9] = "ee";
            arr[9, 10] = "b8";
            arr[9, 11] = "14";
            arr[9, 12] = "de";
            arr[9, 13] = "5e";
            arr[9, 14] = "0b";
            arr[9, 15] = "db";

            arr[10, 0] = "e0";
            arr[10, 1] = "32";
            arr[10, 2] = "3a";
            arr[10, 3] = "0a";
            arr[10, 4] = "49";
            arr[10, 5] = "06";
            arr[10, 6] = "24";
            arr[10, 7] = "5c";
            arr[10, 8] = "c2";
            arr[10, 9] = "d3";
            arr[10, 10] = "ac";
            arr[10, 11] = "62";
            arr[10, 12] = "91";
            arr[10, 13] = "95";
            arr[10, 14] = "e4";
            arr[10, 15] = "79";

            arr[11, 0] = "e7";
            arr[11, 1] = "c8";
            arr[11, 2] = "37";
            arr[11, 3] = "6d";
            arr[11, 4] = "8d";
            arr[11, 5] = "d5";
            arr[11, 6] = "4e";
            arr[11, 7] = "a9";
            arr[11, 8] = "6c";
            arr[11, 9] = "56";
            arr[11, 10] = "f4";
            arr[11, 11] = "ea";
            arr[11, 12] = "65";
            arr[11, 13] = "7a";
            arr[11, 14] = "ae";
            arr[11, 15] = "08";

            arr[12, 0] = "ba";
            arr[12, 1] = "78";
            arr[12, 2] = "25";
            arr[12, 3] = "2e";
            arr[12, 4] = "1c";
            arr[12, 5] = "a6";
            arr[12, 6] = "b4";
            arr[12, 7] = "c6";
            arr[12, 8] = "e8";
            arr[12, 9] = "dd";
            arr[12, 10] = "74";
            arr[12, 11] = "1f";
            arr[12, 12] = "4b";
            arr[12, 13] = "bd";
            arr[12, 14] = "8b";
            arr[12, 15] = "8a";

            arr[13, 0] = "70";
            arr[13, 1] = "3e";
            arr[13, 2] = "b5";
            arr[13, 3] = "66";
            arr[13, 4] = "48";
            arr[13, 5] = "03";
            arr[13, 6] = "f6";
            arr[13, 7] = "0e";
            arr[13, 8] = "61";
            arr[13, 9] = "35";
            arr[13, 10] = "57";
            arr[13, 11] = "b9";
            arr[13, 12] = "86";
            arr[13, 13] = "c1";
            arr[13, 14] = "1d";
            arr[13, 15] = "9e";

            arr[14, 0] = "e1";
            arr[14, 1] = "f8";
            arr[14, 2] = "98";
            arr[14, 3] = "11";
            arr[14, 4] = "69";
            arr[14, 5] = "d9";
            arr[14, 6] = "8e";
            arr[14, 7] = "94";
            arr[14, 8] = "9b";
            arr[14, 9] = "1e";
            arr[14, 10] = "87";
            arr[14, 11] = "e9";
            arr[14, 12] = "ce";
            arr[14, 13] = "55";
            arr[14, 14] = "28";
            arr[14, 15] = "df";


            arr[15, 0] = "8c";
            arr[15, 1] = "a1";
            arr[15, 2] = "89";
            arr[15, 3] = "0d";
            arr[15, 4] = "bf";
            arr[15, 5] = "e6";
            arr[15, 6] = "42";
            arr[15, 7] = "68";
            arr[15, 8] = "41";
            arr[15, 9] = "99";
            arr[15, 10] = "2d";
            arr[15, 11] = "0f";
            arr[15, 12] = "b0";
            arr[15, 13] = "54";
            arr[15, 14] = "bb";
            arr[15, 15] = "16";


        }
        public void convertToBin(string str, ref string binaryString)
        {
            string onebit;

            foreach (char c in str)
            {
                string x = c.ToString();
                onebit = Convert.ToString(Convert.ToInt32(x, 16), 2);
                while (onebit.Length < 4)
                {
                    onebit = "0" + onebit;
                }
                binaryString += onebit;
            }

        }
        public void convertToBin2(string[,] str, ref string[,] binaryMat)
        {
            for (int k = 0; k < 4; k++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string ShiftRowToBinary = "";
                    foreach (char ch in str[k, j])
                    {

                        ShiftRowToBinary = Convert.ToString(Convert.ToInt32(ch.ToString(), 16), 2);

                        while (ShiftRowToBinary.Length < 4)
                        {
                            ShiftRowToBinary = "0" + ShiftRowToBinary;
                        }

                        binaryMat[k, j] += ShiftRowToBinary;
                    }

                }
            }
        }
        public void subByte(string[,] hexaMat, string[,] Sbox, ref string[,] subByteRes)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string temp = hexaMat[i, j];

                    int row = 0;
                    int column = 0;


                    if ((temp[0].ToString()) == "A")
                    {
                        row = 10;
                    }
                    else if ((temp[0].ToString()) == "B")
                    {
                        row = 11;
                    }
                    else if ((temp[0].ToString()) == "C")
                    {
                        row = 12;
                    }
                    else if ((temp[0].ToString()) == "D")
                    {
                        row = 13;
                    }
                    else if ((temp[0].ToString()) == "E")
                    {
                        row = 14;
                    }
                    else if ((temp[0].ToString()) == "F")
                    {
                        row = 15;
                    }
                    else
                    {
                        row = (int)Char.GetNumericValue(temp[0]);
                    }

                    //Check if column = hexa !!
                    if ((temp[1].ToString()) == "A")
                    {
                        column = 10;
                    }
                    else if ((temp[1].ToString()) == "B")
                    {
                        column = 11;
                    }
                    else if ((temp[1].ToString()) == "C")
                    {
                        column = 12;
                    }
                    else if ((temp[1].ToString()) == "D")
                    {
                        column = 13;
                    }
                    else if ((temp[1].ToString()) == "E")
                    {
                        column = 14;
                    }
                    else if ((temp[1].ToString()) == "F")
                    {
                        column = 15;
                    }
                    else
                    {
                        column = (int)Char.GetNumericValue(temp[1]);
                    }

                    subByteRes[i, j] = Sbox[row, column];
                }
            }
        }
        public void subByte1DArray(string[] hexaMat, string[,] Sbox, ref string[] subByteRes)
        {
            for (int i = 0; i < 4; i++)
            {

                string temp = hexaMat[i];

                int row = 0;
                int column = 0;


                if ((temp[0].ToString()) == "A")
                {
                    row = 10;
                }
                else if ((temp[0].ToString()) == "B")
                {
                    row = 11;
                }
                else if ((temp[0].ToString()) == "C")
                {
                    row = 12;
                }
                else if ((temp[0].ToString()) == "D")
                {
                    row = 13;
                }
                else if ((temp[0].ToString()) == "E")
                {
                    row = 14;
                }
                else if ((temp[0].ToString()) == "F")
                {
                    row = 15;
                }
                else
                {
                    row = (int)Char.GetNumericValue(temp[0]);
                }

                //Check if column = hexa !!
                if ((temp[1].ToString()) == "A")
                {
                    column = 10;
                }
                else if ((temp[1].ToString()) == "B")
                {
                    column = 11;
                }
                else if ((temp[1].ToString()) == "C")
                {
                    column = 12;
                }
                else if ((temp[1].ToString()) == "D")
                {
                    column = 13;
                }
                else if ((temp[1].ToString()) == "E")
                {
                    column = 14;
                }
                else if ((temp[1].ToString()) == "F")
                {
                    column = 15;
                }
                else
                {
                    column = (int)Char.GetNumericValue(temp[1]);
                }

                subByteRes[i] = Sbox[row, column];

            }
        }
        public void shiftRows(string[,] subByte, ref string[,] shiftRow)
        {

            shiftRow[0, 0] = subByte[0, 0];
            shiftRow[0, 1] = subByte[0, 1];
            shiftRow[0, 2] = subByte[0, 2];
            shiftRow[0, 3] = subByte[0, 3];

            shiftRow[1, 0] = subByte[1, 1];
            shiftRow[1, 1] = subByte[1, 2];
            shiftRow[1, 2] = subByte[1, 3];
            shiftRow[1, 3] = subByte[1, 0];

            shiftRow[2, 0] = subByte[2, 2];
            shiftRow[2, 1] = subByte[2, 3];
            shiftRow[2, 2] = subByte[2, 0];
            shiftRow[2, 3] = subByte[2, 1];

            shiftRow[3, 0] = subByte[3, 3];
            shiftRow[3, 1] = subByte[3, 0];
            shiftRow[3, 2] = subByte[3, 1];
            shiftRow[3, 3] = subByte[3, 2];

        }
        public void MixColumns(string[,] MixColsMat, string[,] shiftRowsBin, ref string[,] MixColumnsMatrixResult)
        {
            string[] mulRowsbyMClos = new string[4];
            string mulTemp = "", mulTemp1 = "", mulTemp2 = "";
            string oneB = "00011011";
            int counter = 0; char X;
            string ResultBinary = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int w = 0; w < 4; w++)
                    {
                        MixColumnsMatrixResult[j, i] = "";


                        if (MixColsMat[j, w] == "00000001")
                        {
                            mulTemp = shiftRowsBin[w, i];
                            mulRowsbyMClos[counter] = mulTemp;
                            counter++;
                        }
                        else if (MixColsMat[j, w] == "00000010")
                        {
                            //check if the most bit =1 
                            if (shiftRowsBin[w, i][0] == '1')
                            {

                                mulTemp1 = shiftRowsBin[w, i].Substring(1, 7);
                                mulTemp1 += '0';

                                ResultBinary = "";
                                for (int k = 0; k < mulTemp1.Length; k++)
                                {

                                    if (mulTemp1[k] == oneB[k])
                                    {
                                        ResultBinary += "0";
                                    }
                                    else
                                    {
                                        ResultBinary += "1";
                                    }

                                }
                                mulTemp1 = ResultBinary;
                            }
                            else
                            {

                                mulTemp1 = shiftRowsBin[w, i].Substring(1, 7);
                                mulTemp1 += '0';

                            }
                            mulRowsbyMClos[counter] = mulTemp1;

                            counter++;
                        }

                        else
                        {
                            //1st step - same as 02
                            if (shiftRowsBin[w, i][0] == '1')
                            {

                                mulTemp2 = shiftRowsBin[w, i].Substring(1, 7);
                                mulTemp2 += '0';

                                ResultBinary = "";
                                for (int k = 0; k < mulTemp2.Length; k++)
                                {

                                    if (mulTemp2[k] == oneB[k])
                                    {
                                        ResultBinary += "0";
                                    }
                                    else
                                    {
                                        ResultBinary += "1";
                                    }

                                }
                                mulTemp2 = ResultBinary;
                            }
                            //check if the most bit =0
                            else
                            {

                                mulTemp2 = shiftRowsBin[w, i].Substring(1, 7);
                                mulTemp2 += '0';
                            }
                            //Second step Xor with itself

                            ResultBinary = "";
                            for (int k = 0; k < mulTemp2.Length; k++)
                            {
                                string temp = shiftRowsBin[w, i];
                                if (mulTemp2[k] == temp[k])
                                {
                                    ResultBinary += "0";
                                }
                                else
                                {
                                    ResultBinary += "1";
                                }
                            }
                            mulTemp2 = ResultBinary;

                            mulRowsbyMClos[counter] = mulTemp2;

                            counter++;

                        }

                        if (w == 3)
                        {
                            //Xor The 4 result of multiply mixcolumn row wih shiftrow column
                            ResultBinary = "";
                            for (int l = 0; l < 8; l++)
                            {
                                if ((mulRowsbyMClos[0][l] == mulRowsbyMClos[1][l]))
                                {
                                    X = '0';
                                }
                                else
                                {
                                    X = '1';

                                }

                                if (mulRowsbyMClos[2][l] == X)
                                {
                                    X = '0';
                                }
                                else
                                {
                                    X = '1';
                                }
                                if (mulRowsbyMClos[3][l] == X)
                                {
                                    X = '0';
                                }
                                else
                                {
                                    X = '1';
                                }
                                ResultBinary += X;
                            }
                        }
                        MixColumnsMatrixResult[j, i] = ResultBinary;


                    }
                    counter = 0;
                }
            }
        }


    }
}

