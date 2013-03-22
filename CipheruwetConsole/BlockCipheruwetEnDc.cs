using System;
using System.Collections.Generic;
using System.Collections;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CipheruwetConsole
{
    class BlockCipheruwetEnDc
    {
        public BlockCipheruwetEnDc(byte[] key, byte[] input)
        {
            Input = duplicate(input);
            Key = duplicate(key);

            Table = new byte[SIZE];
            r = new Random(sumKeyInput());
        }

        public byte[] encrypt()
        {
            return encryptTransposition(Input);
        }

        public byte[] decrypt()
        {
            return decryptTransposition(Input);
        }

        private byte[] decryptTransposition(byte[] input)
        {
            byte[] temp = transposeKey(input);
            byte[] cipher = new byte[SIZE];

            for (int i = 0; i < SIZE; i++)
            {
                cipher[Table[i]] = temp[i];
            }

            return cipher;
        }

        private byte[] encryptTransposition(byte[] input)
        {
            byte[] temp = transposeKey(input);
            byte[] cipher = new byte[SIZE];

            for (int i = 0; i < SIZE; i++)
            {
                cipher[i] = temp[Table[i]];
            }

            return cipher;
        }

        private byte[] transposeKey(byte[] input)
        {
            byte[] cipher = duplicate(input);
            byte[] key = duplicate(Key);
            for (int i = 0; i < 7; i++)
            {
                cipher = keyXOR(cipher, key);
                byte[] temp = duplicate(key);
                generateRandom();
                for (int j = 0; j < SIZE; j++)
                {
                    key[j] = temp[Table[j]];
                }
            }
            return cipher;
        }

        private byte[] keyXOR(byte[] input, byte[] key)
        {
            byte[] cipher = new byte[SIZE];
            for (int i = 0; i < SIZE; i++)
            {
                cipher[i] = (byte)(input[i] ^ key[i]);
            }
            return cipher;
        }

        private void generateRandom()
        {
            for (int i = 0; i < SIZE; i++)
            {
                Table[i] = 0;
            }

            for (int i = 1; i < SIZE; i++)
            {
                int x = r.Next(SIZE);
                while (Table[x] != 0)
                {
                    x = (x + 1) % SIZE;
                }
                Table[x] = (byte)i;
            }
        }

        private int sumKeyInput()
        {
            int x = 0;
            for (int i = 0; i < SIZE; i++)
            {
                x = (x + Key[i]) % (1 << 16);
                x = (x + Input[i]) % (1 << 16);
            }
            return x;
        }

        private byte[] duplicate(byte[] x)
        {
            byte[] ret = new byte[x.Length];
            for (int i = 0; i < x.Length; i++)
            {
                ret[i] = x[i];
            }
            return ret;
        }

        private byte[] Key;
        private byte[] Input;

        private byte[] Table;
        private Random r;

        public const int SIZE = (1 << 3);
    }
}
