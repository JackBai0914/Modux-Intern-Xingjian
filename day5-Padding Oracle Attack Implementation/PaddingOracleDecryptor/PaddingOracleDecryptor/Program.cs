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

            Attack.Oracles.AES_CBCOracle aes = new Attack.Oracles.AES_CBCOracle ();
            Attack.Attacker attacker = new Attack.Attacker (aes);
            string clearText = "And what, Socrates, is the food of the soul? Surely, I said, knowledge is the food of the soul. -- Plato";
            byte[] cipher = aes.AES_EncryptString (clearText);

            string plainText = attacker.Decrypt(cipher);
            Console.WriteLine("\n>>>>>>>>> Decryption result <<<<<<<<<<<:\n{0}", plainText);

            Console.ReadKey();
        }
    }
}
