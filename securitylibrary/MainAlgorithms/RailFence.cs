using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            int maxkey = plainText.Length ; 
            for(int i =1; i <= maxkey; i++)
            { 
           
                string cipher = Encrypt(plainText, i);
               
                if (cipher == cipherText.ToLower())
                {
                    return i;
                }
               
            }
            return 0;


        }

        public string Decrypt(string cipherText, int key)
        {
            // throw new NotImplementedException();
            string plainText = "";
            int columns = cipherText.Length / key;
            int cipherLen = 0;

            if (cipherText.Length % key != 0)
                   columns++;
                
             char[,] plain = new char[key, columns];
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    if (cipherLen != cipherText.Length)
                    {
                        plain[i, j] = cipherText[cipherLen];
                        cipherLen++;
                    }
                    else
                        break;
                }
            }
            for (int j = 0; j < columns; j++)
            {
                for (int i = 0; i < key; i++)
                {
                    plainText += plain[i, j];
                }
            }

            return plainText;
            
              
        }

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            string cipherText = "";
            for (int i = 0; i < key; i++)
            {
                for (int j = i; j < plainText.Length; j += key)
                {
                    cipherText += plainText[j];
                }
            }
            return cipherText;
        }
    }
}
