using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
            List<int> keys = new List<int>();
            int key1, key2;
            int alphaXA_mod_q, alphaXB_mod_q;
            alphaXA_mod_q = modRes(xa, alpha, q);
            alphaXB_mod_q = modRes(xb, alpha, q);
            key1 = modRes(xa, alphaXB_mod_q, q);
            key2 = modRes(xb, alphaXA_mod_q, q);
            keys.Add(key1);
            keys.Add(key2);
            return keys;


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
