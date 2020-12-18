/*
 * author: martani (martani.net@gmail.com)
 * copyright 2013
 * 
 */
using System;
//using PaddingOracleAttackLib;
using Attack;


namespace PaddingOracle
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            //using other's local encypher class
            Attack.Oracles.AES_CBCOracle aes = new Attack.Oracles.AES_CBCOracle ();


            Attack.Attacker attacker = new Attack.Attacker (aes);
            string clearText = "***********";
            byte[] cipher = aes.AES_EncryptString (clearText);

            string plainText = attacker.Decrypt(cipher);
            Console.WriteLine("\nDecryption result: \n{0}", plainText);
            Console.ReadKey();
        }
    }
}
