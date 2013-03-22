using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CipheruwetConsole
{
    class BlockCipheruwet
    {
        public BlockCipheruwet(byte[] input, byte[] key)
        {
            Input = duplicate(input);
            Key = duplicate(key);
        }

        public byte[] encrypt()
        {
            return encryptFeistel();
        }

        public byte[] decrypt()
        {
            return decryptFeistel();
        }

        private byte[] decryptFeistel()
        {
            initialization();
            byte[] tempCipherA = new byte[SIZE7];
            byte[] tempCipherB = new byte[SIZE7];

            for (int i = 0; i < FEISTEL_COUNT; i++)
            {
                tempCipherB = duplicate(CipherA);
                tempCipherA = bitwiseXOR(CipherB, new BlockCipheruwetEnDc(Key, CipherA).encrypt());

                CipherA = duplicate(tempCipherA);
                CipherB = duplicate(tempCipherB);
            }

            byte[] ret = new byte[SIZE8];
            int k = 0;
            for (; k < SIZE7; k++)
            {
                ret[k] = CipherA[k];
            }
            for (int j = 0; k < SIZE8; k++, j++)
            {
                ret[k] = CipherB[j];
            }

            return ret;
        }

        private byte[] encryptFeistel()
        {
            initialization();
            byte[] tempCipherA = new byte[SIZE7];
            byte[] tempCipherB = new byte[SIZE7];
            for (int i = 0; i < FEISTEL_COUNT; i++)
            {
                tempCipherA = duplicate(CipherB);
                tempCipherB = bitwiseXOR(CipherA, new BlockCipheruwetEnDc(Key, CipherB).encrypt());

                CipherA = duplicate(tempCipherA);
                CipherB = duplicate(tempCipherB);
            }

            byte[] ret = new byte[SIZE8];
            int k = 0;
            for (; k < SIZE7; k++)
            {
                ret[k] = CipherA[k];
            }
            for (int j = 0; k < SIZE8; k++, j++)
            {
                ret[k] = CipherB[j];
            }

            return ret;
        }

        private byte[] bitwiseXOR(byte[] A, byte[] B)
        {
            byte[] ret = new byte[A.Length];
            for (int i = 0; i < A.Length; i++)
            {
                ret[i] = (byte)(A[i] ^ B[i]);
            }
            return ret;
        }

        private void initialization()
        {
            CipherA = new byte[SIZE7];
            CipherB = new byte[SIZE7];
            int i = 0;
            for (; i < SIZE7; i++)
            {
                CipherA[i] = Input[i];
            }
            for (int k = 0; i < SIZE8; i++, k++)
            {
                CipherB[k] = Input[i];
            }
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

        private byte[] Input;
        private byte[] Key;
        private byte[] CipherA;
        private byte[] CipherB;

        public const int SIZE8 = (1 << 4);
        public const int SIZE7 = (1 << 3);
        public const int FEISTEL_COUNT = (1 << 4);
    }
}
