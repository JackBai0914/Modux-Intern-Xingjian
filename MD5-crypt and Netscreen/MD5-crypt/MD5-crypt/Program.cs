using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace MD5_crypt
{
    class MD5_crypt
    {
        private static String magic = "$1$";
        private static String bittable = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"; //64 bits, as intended

        //byte concatenation
        private static byte[] Concat (byte[] x, byte[] y)
        {
            byte[] ret = new byte[x.Length + y.Length];
            System.Buffer.BlockCopy(x, 0, ret, 0, x.Length);
            System.Buffer.BlockCopy(y, 0, ret, x.Length, y.Length);
            return ret;
        }
        private static byte[] PartialConcat(byte[] x, byte[] y, int max)
        {
            byte[] ret = new byte[x.Length + max];
            System.Buffer.BlockCopy(x, 0, ret, 0, x.Length);
            System.Buffer.BlockCopy(y, 0, ret, x.Length, max);
            return ret;
        }

        //encode integer to base64
        private static String to64 (int v, int l)
        {
            StringBuilder ret = new StringBuilder();
            while (--l >= 0)
            {
                ret.Append(bittable.Substring(v & 0x3f, 1));
                v >>= 6;
            }
            return ret.ToString();
        }

        //md5-crypt
        public static string crypt (String password, String salt)
        {
            HashAlgorithm x_hash_alg = HashAlgorithm.Create("MD5");

            if (salt.StartsWith(magic))
                //remove the possible overlaping
                salt = salt.Substring(magic.Length);
            if (salt.LastIndexOf('$') != -1)
                //remove the possible hashing at the end of salt
                salt = salt.Substring(0, salt.LastIndexOf('$'));
            if (salt.Length > 8)
                //only 8 Bytes are needed
                salt = salt.Substring(0, 8);

            byte[] combined = Encoding.ASCII.GetBytes(password + magic + salt);
            byte[] final = x_hash_alg.ComputeHash(Encoding.ASCII.GetBytes((password + salt + password)));

            //Console.WriteLine(combined.Length);
            //Console.WriteLine(final.Length);
            //Console.WriteLine(Encoding.Default.GetString(combined));
            //Console.WriteLine(Encoding.Default.GetString(final));

            for (int len = password.Length; len > 0; len -= 16)
            {
                if (len > 16)   combined = Concat(combined, final);
                else            combined = PartialConcat(combined, final, len);
            }

            byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
            for (int i = password.Length; i > 0; i >>= 1)
                if (i % 2 != 0) combined = Concat(combined, new byte[] { 0 });
                else            combined = Concat(combined, new byte[] { passwordBytes[0] });


            final = x_hash_alg.ComputeHash(combined);
            byte[] saltBytes = Encoding.ASCII.GetBytes(salt);
            for (int i = 0; i < 1000; i++)
            {
                byte[] combined1 = new byte[] { };
                if (i % 2 != 0) combined1 = Concat(combined1, passwordBytes);
                else            combined1 = Concat(combined1, final);
                if (i % 3 != 0) combined1 = Concat(combined1, saltBytes);
                if (i % 7 != 0) combined1 = Concat(combined1, passwordBytes);
                if (i % 2 == 0) combined1 = Concat(combined1, passwordBytes);
                else            combined1 = Concat(combined1, final);
                final = x_hash_alg.ComputeHash(combined1);
            }

            // Add the password hash to the result string
            StringBuilder result = new StringBuilder();
            result.Append(to64(((final[0] & 0xff) << 16) | ((final[6] & 0xff) << 8) | (final[12] & 0xff), 4));
            result.Append(to64(((final[1] & 0xff) << 16) | ((final[7] & 0xff) << 8) | (final[13] & 0xff), 4));
            result.Append(to64(((final[2] & 0xff) << 16) | ((final[8] & 0xff) << 8) | (final[14] & 0xff), 4));
            result.Append(to64(((final[3] & 0xff) << 16) | ((final[9] & 0xff) << 8) | (final[15] & 0xff), 4));
            result.Append(to64(((final[4] & 0xff) << 16) | ((final[10] & 0xff) << 8) | (final[5] & 0xff), 4));
            result.Append(to64(final[11] & 0xff, 2));
            //result.Length should be 4*5+2=22
            return magic + salt + "$" + result.ToString();
        }


        static void Main(string[] args)
        {
            //$1$28772684$iEwNOgGugqO9.bIz5sk8k/
            string salt = "28772684";
            string target = "$1$28772684$iEwNOgGugqO9.bIz5sk8k/";

            string[] lines = System.IO.File.ReadAllLines(@"/Users/jackbai/Projects/day2/MD5-crypt/MD5-crypt/pw.txt");
            foreach (string str in lines) {
                string password = str;
                string md5crypt = crypt(password, salt);
                if (md5crypt == target)
                {
                    Console.WriteLine("found it!");
                    Console.WriteLine(password);
                }
            }
            //Console.WriteLine(crypt(password, salt));
        }
    }
}
