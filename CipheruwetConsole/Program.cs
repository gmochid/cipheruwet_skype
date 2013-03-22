using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SKYPE4COMLib;

namespace CipheruwetConsole
{
    class Program
    {
        static int SIZE = (1 << 4);

        static void Main(string[] args)
        {
            Skype skype = new Skype();

            Console.WriteLine("Enkripsi/Dekripsi Skype");
            Console.WriteLine("1. Mode enkripsi");
            Console.WriteLine("2. Mode dekripsi");
            Console.WriteLine("Masukkan mode : ");

            int mode = Convert.ToInt32(Console.ReadLine());

            if (mode == 1)
            {
                // ask input from user
                Console.Write("Masukkan username dari penerima: ");
                String tujuan = Console.ReadLine();
                Console.Write("Masukkan pesan yang akan dienkripsi: ");
                String pesan = Console.ReadLine();
                Console.Write("Masukkan kunci yang enkripsi: ");
                String key = Console.ReadLine();

                int len = pesan.Length;
                int cipherLen = 0;
                while (cipherLen < len)
                {
                    cipherLen += SIZE;
                }

                byte[] cipher = new byte[cipherLen];
                byte[] temp = new byte[SIZE];
                int i = 0, k = 0; ;
                while (i < cipherLen)
                {
                    for (int j = 0; j < SIZE; j++)
                    {
                        if (i < len)
                        {
                            temp[j] = (byte) pesan[i++];
                        }
                        else
                        {
                            temp[j] = 0;
                            i++;
                        }
                    }

                    temp = new BlockCipheruwet(temp, PadByteArray(toByte(key))).encrypt();
                    for (int j = 0; j < SIZE; j++)
                    {
                        cipher[k++] = temp[j];
                    }
                }
                
                Test.print(cipher);
                Console.WriteLine(toString(cipher));
                skype.SendMessage(tujuan, toString(cipher));
            }
            else
            {
                Console.Write("Masukkan string yang akan didekripsi: ");
                String cipher = Console.ReadLine();
                Console.Write("Masukkan kunci yang enkripsi: ");
                String key = Console.ReadLine();

                int len = cipher.Length;

                byte[] temp = new byte[SIZE];
                int i = 0;
                int k = 0;
                byte[] PL = new byte[len];
                while (i < len)
                {
                    for (int j = 0; j < SIZE; j++)
                    {
                        temp[j] = (byte) cipher[i++];
                    }

                    temp = new BlockCipheruwet(temp, PadByteArray(toByte(key))).decrypt();
                    for (int j = 0; j < SIZE; j++)
                    {
                        PL[k++] = temp[j];
                    }
                }

                Test.print(PL);
                Console.WriteLine(toString(PL));
            }
        }

        public static byte[] toByte(String s)
        {
            byte[] x = new byte[s.Length];
            for (int i = 0; i < s.Length; i++)
            {
                x[i] = (byte) s[i];
            }
            return x;
        }

        public static String toString(byte[] b)
        {
            char[] x = new char[b.Length];
            for (int i = 0; i < b.Length; i++)
            {
                x[i] = (char) b[i];
            }
            return new String(x);
        }

        static byte[] PadByteArray(byte[] source, int length = 16, byte pad = 0)
        {
            byte[] paddedByteArray = new byte[length];
            for (int i = 0; i < length; i++)
            {
                if (i < source.Length)
                    paddedByteArray[i] = source[i];
                else
                    paddedByteArray[i] = pad;
            }

            return paddedByteArray;
        }

        static byte[] CropByteArray(byte[] source, long length)
        {
            byte[] croppedByteArray = new byte[length];
            for (int i = 0; i < length; i++)
            {
                croppedByteArray[i] = source[i];
            }

            return croppedByteArray;
        }
    }
}
