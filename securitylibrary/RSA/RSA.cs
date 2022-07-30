using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            //throw new NotImplementedException();
            int n = p * q;
            int Qn = (p - 1) * (q - 1);
            int enc = modRes(e, M, n);
            return enc;

        }

        public int Decrypt(int p, int q, int C, int e)
        {
           //throw new NotImplementedException();
           ExtendedEuclid inverse = new ExtendedEuclid();
            int n = p * q;
            int Qn = (p - 1) * (q - 1);
            int d = inverse.GetMultiplicativeInverse(e, Qn);
            int dec = modRes(d, C, n);
            return dec;

        }
        public int modRes(int x, int y, int q)
        {
            int res = y;
            for (int i = 1; i < x; i++)
            {
                res = (res * y) % q;
            }
            
            return res;

        }
    }
}
