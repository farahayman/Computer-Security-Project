using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();
            int res = 0;
            int[,] arr = new int[1000, 7];
            arr[0, 0] = 0;
            arr[0, 1] = 1;
            arr[0, 2] = 0;
            arr[0, 3] = baseN;
            arr[0, 4] = 0;
            arr[0, 5] = 1;
            arr[0, 6] = number;
            for (int i = 1; i < arr.GetLength(0); i++)
            {
                for (int j = 0; j < arr.GetLength(1); j++)
                {
                    if (j == 0)
                    {
                        arr[i, j] = arr[i - 1, 3] / arr[i - 1, 6];
                    }
                    else if (j == 1)
                    {
                        arr[i, j] = arr[i - 1, 4];
                    }
                    else if (j == 2)
                    {
                        arr[i, j] = arr[i - 1, 5];
                    }
                    else if (j == 3)
                    {
                        arr[i, j] = arr[i - 1, 6];

                    }
                    else if (j == 4)
                    {
                        arr[i, j] = arr[i - 1, 1] - (arr[i, 0] * arr[i - 1, 4]);
                    }
                    else if (j == 5)
                    {
                        arr[i, j] = arr[i - 1, 2] - (arr[i, 0] * arr[i - 1, 5]);
                    }
                    else if (j == 6)
                    {
                        arr[i, j] = arr[i - 1, 3] - (arr[i, 0] * arr[i - 1, 6]);
                    }

                }
                if (arr[i, 6] == 1)
                {
                    res = arr[i, 5] ;
                    break;
                }
                else if (arr[i, 6] == 0)
                {
                    res = -1;
                    break;
                }

            }
            if (res < -1)
            {
                res += baseN;
            }
            return res;
        }
    }
}
