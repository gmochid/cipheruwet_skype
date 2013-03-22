using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CipheruwetConsole
{
    class Test
    {
        static void testBC()
        {
            Random r = new Random();
            byte[] input = new byte[1 << 8];
            byte[] key = new byte[1 << 8];
            r.NextBytes(input);
            r.NextBytes(key);

            Console.WriteLine("Input:");
            print(input);
            Console.WriteLine("Key:");
            print(key);

            BlockCipheruwet Block = new BlockCipheruwet(input, key);
            Console.WriteLine("EN:");
            print(Block.encrypt());

            BlockCipheruwet Block2 = new BlockCipheruwet(Block.encrypt(), key);
            Console.WriteLine("DC:");
            print(Block2.decrypt());
        }

        static void testBCED()
        {
            Random r = new Random();
            byte[] input = new byte[1 << 8];
            byte[] key = new byte[1 << 8];
            r.NextBytes(input);
            r.NextBytes(key);

            Console.WriteLine("Input:");
            print(input);
            Console.WriteLine("Key:");
            print(key);

            BlockCipheruwetEnDc Block = new BlockCipheruwetEnDc(key, input);

            Console.WriteLine("Cipher:");
            print(Block.encrypt());

            BlockCipheruwetEnDc Block2 = new BlockCipheruwetEnDc(key, Block.encrypt());

            Console.WriteLine("PL:");
            print(Block2.decrypt());
        }

        public static void print(byte[] x)
        {
            for (int i = 0; i < x.Length; i++)
            {
                Console.Write(x[i]);
                Console.Write(" ");
            }
            Console.WriteLine();
        }
    }
}
