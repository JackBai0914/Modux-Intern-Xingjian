using System;
using System.Collections.Generic;
using StringFunctions;

namespace Attack
{
	public interface Query
	{
		bool query(byte[] cipher);
	}

	public class Attacker
	{
		const int BLOCK_SIZE = 16;

		private Query query_tool;

		public Attacker(Query oracle)
		{
			query_tool = oracle;
		}

		// Decrypt using the Padding Oracle Attack
		public string Decrypt(string hexCipher)
		{
			return Decrypt(Helpers.ConvertHexStringToByteArray(hexCipher));
		}
		public string Decrypt(byte[] cipher)
		{
			//Split the cipher into blocks of BLOCK_SIZE bytes
			int blockNum = cipher.Length / BLOCK_SIZE;

			byte[][] cipherBlocks = new byte[blockNum][];

			for (int i = 0; i < blockNum; i++)
			{
				cipherBlocks[i] = new byte[BLOCK_SIZE];
				Array.Copy(cipher, i * BLOCK_SIZE, cipherBlocks[i], 0, BLOCK_SIZE);
			}

			string plainText = "";
			for (int i = 1; i < blockNum; i++)
			{
				Console.WriteLine("\n[[[ Decrypting Block {0}/{1} ]]]", i, cipherBlocks.Length - 1);
				string tmps = this.DecryptBlock(cipherBlocks[i], cipherBlocks[i - 1]);
				plainText += tmps;
				Console.WriteLine("\n>>> Decryted block {0}: {1}", i, tmps);
			}
			return plainText;
		}


		/// Decrypts one block at a time using Padding Oracle Attack.
		private string DecryptBlock(byte[] block, byte[] IV)
		{
			byte[] decryptedBlock = new byte[16];
			int paddingLen = DecryptLastNBytes(block, IV, decryptedBlock);
			for (int i = 0; i < block.Length - paddingLen; i++)
				DecryptByteAtPosition(block, IV, block.Length - 1 - paddingLen - i, decryptedBlock);
			return Helpers.ConvertByteArrayToUTF8String(Helpers.Xor(decryptedBlock, IV););
		}

		// Decrypts the last N bytes in a block, for an X padding (ie. [DATA...XXXXX]), it decrypts the last X bytes.
		private int DecryptLastNBytes(byte[] cipherBlock, byte[] IV, byte[] resultDecrypted)
		{
			byte[] payload = new byte[cipherBlock.Length * 2];
			Random r = new Random();
			r.NextBytes(payload);

			Array.Copy(cipherBlock, 0, payload, cipherBlock.Length, cipherBlock.Length);

			foreach (var b in GetCharsOrdered(IV[cipherBlock.Length - 1]))
			{
				payload[cipherBlock.Length - 1] = b;
				if (this.query_tool.query(payload))
				{
					Console.WriteLine("\rGot last byte");
					break;
				}
			}

			byte lastChangedByte;
			int paddingLength = 1;

			for (int i = 0; i < cipherBlock.Length - 1; i++)
			{
				lastChangedByte = payload[i];
				payload[i]++;

				if (this.query_tool.query(payload) == false)
				{
					paddingLength = cipherBlock.Length - i;
					Console.WriteLine("\rDecrypted");

					payload[i] = lastChangedByte;
					break;
				}
				payload[i] = lastChangedByte;
			}

			for (int i = 0; i < paddingLength; i++)
			{
				resultDecrypted[cipherBlock.Length - i - 1] = (byte)(paddingLength ^ payload[cipherBlock.Length - i - 1]);
			}

			return paddingLength;
		}

		// Decrypts a byte from the block at a specific position.
		private void DecryptByteAtPosition(byte[] cipherBlock, byte[] IV, int bytePosition, byte[] resultDecrypted)
		{
			byte[] payload = new byte[cipherBlock.Length * 2];
			Random r = new Random();
			r.NextBytes(payload);

			Array.Copy(cipherBlock, 0, payload, cipherBlock.Length, cipherBlock.Length);

			int j = bytePosition + 1;

			for (int k = j; k < BLOCK_SIZE; k++)
				payload[k] = (byte)(resultDecrypted[k] ^ (BLOCK_SIZE - (1 + j) + 2));

			int i = 0;
			foreach (var c in GetCharsOrdered((byte)(IV[bytePosition] ^ (BLOCK_SIZE - (1 + j) + 2))))
			{
				payload[bytePosition] = c;

				if (this.query_tool.query(payload))
				{
					Console.Write("\rByte {0} --\t {1} Oracle calls\n", bytePosition, i);
					break;
				}

				++i;
			}
			resultDecrypted[bytePosition] = (byte)(payload[bytePosition] ^ (BLOCK_SIZE - (1 + j) + 2));
		}

		
		private static IEnumerable<byte> GetCharsOrdered(byte IV)
		{
			List<Tuple<byte, byte>> charsPriorityLevels = new List<Tuple<byte, byte>>();

			charsPriorityLevels.Add(new Tuple<byte, byte>(97, 126));    //a-z
			charsPriorityLevels.Add(new Tuple<byte, byte>(65, 96));     //A-Z
			charsPriorityLevels.Add(new Tuple<byte, byte>(32, 66));     //punctuations
			charsPriorityLevels.Add(new Tuple<byte, byte>(0, 31));
			charsPriorityLevels.Add(new Tuple<byte, byte>(127, 255));

			foreach (var item in charsPriorityLevels)
			{
				for (int i = item.Item1; i <= item.Item2; i++)
				{
					yield return (byte)(i ^ IV);
				}
			}
		}
	}
}

