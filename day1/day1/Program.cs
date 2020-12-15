using System;

namespace Xor_Key_Xingjian_1
{
    using System;
    using System.Security.Cryptography;
    using System.Text;
    class Program
    {
        static string string_to_hex(string s)
        {
            string ans = "";
            foreach (char c in s)
            {
                if (((int)c).ToString("X").Length == 1)
                    ans += "0";
                ans += ((int)c).ToString("X");
            }
            return ans;
        }
        static string hex_to_int(string s)
        {
            System.Numerics.BigInteger t = System.Numerics.BigInteger.Parse(s,
                System.Globalization.NumberStyles.AllowHexSpecifier);
            return t.ToString();
        }
        static string Xor(long x, long y)
        {
            return (x ^ y).ToString();
        }
        static System.Numerics.BigInteger Xor(System.Numerics.BigInteger x, System.Numerics.BigInteger y)
        {
            return x ^ y;
        }
        static string Xor(string x, string y)
        {
            string ans = "";
            for (int i = 0; i < Math.Min(y.Length, x.Length); i++)
                ans += (char)(Convert.ToInt32(x[i]) ^ Convert.ToInt32(y[i]));
            for (int i = Math.Min(y.Length, x.Length); i < x.Length; i++)
                ans += (char)(Convert.ToInt32(x[i]));
            for (int i = Math.Min(y.Length, x.Length); i < y.Length; i++)
                ans += (char)(Convert.ToInt32(y[i]));
            return ans;
        }
        static string Xor_int(string x, string y)
        {
            System.Numerics.BigInteger x0 = System.Numerics.BigInteger.Parse(x);
            System.Numerics.BigInteger y0 = System.Numerics.BigInteger.Parse(y);
            return Xor(x0, y0).ToString();
        }
        static string Xor(string x, long y)
        {
            System.Numerics.BigInteger x0 = System.Numerics.BigInteger.Parse(string_to_hex(x), System.Globalization.NumberStyles.AllowHexSpecifier);
            System.Numerics.BigInteger y0 = System.Numerics.BigInteger.Parse(y.ToString());
            return Xor(x0, y0).ToString();
        }
        static string Big_to_ascii(System.Numerics.BigInteger x)
        {
            long x0 = (long)x;
            string ans = "";
            while (x0 > 0)
            {
                long cur = x0 % 256;
                if (cur >= 128)
                    return "";
                ans += (char)(cur);
                x0 /= 256;
            }
            return Reverse(ans);
        }
        public static string Reverse(string s)
        {
            char[] charArray = s.ToCharArray();
            Array.Reverse(charArray);
            return new string(charArray);
        }


        static string key = "thisisthekeytoenhanceMD5";
        public static string MD5Crypt(string s)
        {
            s = Xor(s, key);
            using (var md5Hash = MD5.Create())
            {
                var sourceBytes = Encoding.UTF8.GetBytes(s);
                var hashBytes = md5Hash.ComputeHash(sourceBytes);
                var hash = BitConverter.ToString(hashBytes).Replace("-", string.Empty);
                return hash;
            }

        }

        static void Main(string[] args)
        {

            long a = 10000;
            long b = 12345;
            Console.WriteLine(Xor(a, b));
            //TASK1
            //System.Numerics.BigInteger tg2 = System.Numerics.BigInteger.Parse(tg1.ToString());
            //long tg3 = (long)tg2;
            //for (long i = tg3 - 128; i <= tg3 + 128; i ++)
            //{
            //    System.Numerics.BigInteger x = System.Numerics.BigInteger.Parse(i.ToString());
            //    long y = (long)Xor(tg2, x);
            //    //long z = i ^ y;
            //    if (y >= 100)
            //        continue;
            //    string x_str = Big_to_ascii(x);
            //    if (x_str == "")
            //        continue;
            //    //Console.WriteLine(y);
            //    //Console.WriteLine(x_str);

            //    //if (x_str != "" && y < 100)
            //    //{
            //    //    Console.WriteLine(x_str);
            //    //    Console.WriteLine(y);
            //    //    Console.WriteLine(Xor(x_str, (long)y));
            //    //}
            //}

            //TASK2
            //Console.WriteLine("start here:");
            //// Creates an instance of the default implementation of the MD5 hash algorithm.
            //for (int i = 0; i < 1000; i++)
            //{
            //    using (var md5Hash = MD5.Create())
            //    {
            //        var sourceBytes = Encoding.UTF8.GetBytes(array1[i]);
            //        var hashBytes = md5Hash.ComputeHash(sourceBytes);
            //        var hash = BitConverter.ToString(hashBytes).Replace("-", string.Empty);
            //        if (hash == "CF9EE5BCB36B4936DD7064EE9B2F139E")
            //            Console.WriteLine("The MD5 hash of " + array1[i] + " is: " + hash);
            //    }
            //}

            //hello
            //TASK3
            //string s = "hello world";
            //string t = MD5Crypt(s);

        }
    }
}
