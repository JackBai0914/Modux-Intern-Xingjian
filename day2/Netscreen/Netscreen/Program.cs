using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Netscreen
{
    class Netscreen_Crypt
    {
        static String b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        static HashAlgorithm x_hash_alg = HashAlgorithm.Create("MD5");
       
        private static byte[] string_MD5(String s)
        {
            return x_hash_alg.ComputeHash(Encoding.ASCII.GetBytes(s));
        }

        //crypt
        public static String crypt(String password, String user)
        {
            //step1: MD5
            String middle = "Administration Tools";
            String s = user + ":" + middle + ":" + password;
            byte[] s1 = string_MD5(s);

            //for testing
            Console.Write("The MD5 code encrypted: ");
            for (int i = 0; i < s1.Length; i++)
            {
                Console.Write(s1[i]);
                Console.Write(" ");
            }
            Console.WriteLine();

            //step2: 1st Shuffle
            int[] s2 = {0, 0, 0, 0, 0, 0, 0, 0};
            for (int i = 0; i < 8; i++)
                s2[i] = (s1[i * 2] << 8 & 0xff00) | (s1[i * 2 + 1] & 0xff);

            //step3: 2ed Shuffle
            StringBuilder res = new StringBuilder();
            foreach (int x in s2)
            {
                res.Append(b64[x >> 12 & 0xf]);
                res.Append(b64[x >> 6 & 0x3f]);
                res.Append(b64[x & 0x3f]);
            }

            //step4: Blend
            String result = res.ToString();
            result = "n" + result.Substring(0, 5) +
                     "r" + result.Substring(5, 5) +
                     "c" + result.Substring(10, 4) +
                     "s" + result.Substring(14, 5) +
                     "t" + result.Substring(19, 5) + "n";

            //Console.WriteLine(result);
            return result;
        }

        //reverse crypt
        public static byte[] reverse_crypt(String ns)
        {
            //reverse Blend
            StringBuilder hash = new StringBuilder();
            int[] index = {1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 13, 14, 15, 16, 18, 19, 20, 21, 22, 24, 25, 26, 27, 28};
            foreach (int i in index)
                hash.Append(ns[i]);
            //Console.WriteLine(hash);

            //reverse 2ed Shuffle
            int[] mid = {0, 0, 0, 0, 0, 0, 0, 0 }; 
            int[] index2 = { 2, 5, 8, 11, 14, 17, 20, 23 };
            for (int i = 0; i < 8; i ++)
            {
                int p1 = b64.IndexOf(hash[index2[i] - 2]);
                int p2 = b64.IndexOf(hash[index2[i] - 1]);
                int p3 = b64.IndexOf(hash[index2[i] - 0]);
                mid[i] = (p1 << 12 | p2 << 6 | p3);
                //Console.WriteLine(mid[i]);
            }

            //reverse 1st Shuffle
            byte[] md5 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            for (int i = 0; i < mid.Length; i ++)
            {
                md5[i * 2] = (byte)(mid[i] >> 8);
                md5[i * 2 + 1] = (byte)(mid[i] & 0xff);
            }
            Console.Write("The MD5 code decrypted: ");
            for (int i = 0; i < md5.Length; i++)
            {
                Console.Write(md5[i]);
                Console.Write(" ");
            }
            Console.WriteLine();
            return md5;
        }


        static void Main(string[] args)
        {
            string user = "asfasdfat21hjk34hl3u5yo9pg8dfys908w4ersdfasdf";
            string password = "htlwrjkeyeljwjgheljkgthrelkjghwelrkgfsdiopugy23452345";

            string code = crypt(password, user);

            byte[] md5hash = reverse_crypt(code);
        }
    }
}
