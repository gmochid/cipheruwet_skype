using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace CipheruwetConsole
{
    class Engine
    {
        public const byte ECB = 1;
        public const byte CBC = 2;
        public const byte CFB = 3;
        public const byte OFB = 4;

        public static BlockCipheruwet Cipher;

        private static byte[] XorByteArray(byte[] a, byte[] b)
        {
            byte[] c = new byte[a.Length];

            for (int i = 0; i < c.Length; ++i)
            {
                c[i] = Convert.ToByte(a[i] ^ b[i]);
            }

            return c;
        }

        private static byte[] PadByteArray(byte[] source, int length = 16, byte pad = 0)
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

        private static byte[] CropByteArray(byte[] source, long length)
        {
            byte[] croppedByteArray = new byte[length];
            for (int i = 0; i < length; i++)
            {
                croppedByteArray[i] = source[i];
            }

            return croppedByteArray;
        }

        /// <summary>
        /// Encrypt a given source file and save it to a given target file.
        /// </summary>
        /// <param name="sourceFileName">The filename of the source file. Presumed to exist.</param>
        /// <param name="destinationFileName">The filename of the target file. Will be overwritten.</param>
        /// <param name="key">The key to encrypt with</param>
        /// <param name="mode">The mode of encryption. Use Engine.* constants.</param>
        /// <param name="blockSize">The chosen block size.</param>
        public static void StartEncryption(String sourceFileName, String destinationFileName, String key, byte mode, int blockSize = 16)
        {
            if (mode != ECB && mode != CBC && mode != CFB && mode != OFB)
            {
                throw new Exception("Invalid block cipher mode of operation.");
            }

            // Auxiliary variables
            byte[] crlf = { Convert.ToByte('\r'), Convert.ToByte('\n') };
            char[] keyChars = key.ToCharArray();
            byte[] keyBytes = new byte[key.Length];
            for (var i = 0; i < key.Length; ++i)
            {
                keyBytes[i] = Convert.ToByte(keyChars[i]);
            }

            // Open read handle. Treat all files as binary.
            FileStream fr = File.OpenRead(sourceFileName);
            BinaryReader br = new BinaryReader(fr);

            // Open write handle.
            FileStream fw = File.OpenWrite(destinationFileName);
            BinaryWriter bw = new BinaryWriter(fw);

            // Start by writing the header

            // The header consists of the following bytes:
            //  1-8  Original file length
            //  9-12 Block size
            // 13    Block cipher mode of operation
            // 14-15 CRLF
            // 16-.. Initialization vector (according to blocksize)
            // ..-.. CRLF

            Int64 originalLength = Convert.ToInt64(fr.Length);
            Console.WriteLine(originalLength.ToString("X8"));
            bw.Write(originalLength);

            Int32 blockSizeField = Convert.ToInt32(blockSize);
            bw.Write(blockSizeField);

            bw.Write(mode);

            bw.Write(crlf);

            Random iv = new Random();
            byte[] initializationVector = new byte[blockSize];
            iv.NextBytes(initializationVector);
            bw.Write(initializationVector);

            bw.Write(crlf);

            // Header is written.

            // Write body
            long pos = 0;
            long length = fr.Length;
            byte[] readBuffer;
            byte[] paddedBuffer;
            BlockCipheruwet Cipher;

            byte[] previousBlock = (byte[])initializationVector.Clone();

            while (pos < length)
            {
                // Load one block into buffer
                readBuffer = br.ReadBytes(blockSize);
                paddedBuffer = PadByteArray(readBuffer, blockSize);
                byte[] cipherBuffer;
                byte[] pre;

                switch (mode)
                {
                    case ECB:
                        Cipher = new BlockCipheruwet(paddedBuffer, keyBytes);
                        bw.Write(Cipher.encrypt());
                        break;
                    case CBC:
                        pre = XorByteArray(paddedBuffer, previousBlock);
                        Cipher = new BlockCipheruwet(pre, keyBytes);
                        cipherBuffer = Cipher.encrypt();
                        bw.Write(cipherBuffer);
                        Array.Copy(cipherBuffer, previousBlock, blockSize);
                        break;
                    case CFB:
                        Cipher = new BlockCipheruwet(previousBlock, keyBytes);
                        pre = Cipher.encrypt();
                        cipherBuffer = XorByteArray(pre, paddedBuffer);
                        bw.Write(cipherBuffer);
                        Array.Copy(cipherBuffer, previousBlock, blockSize);
                        break;
                    case OFB:
                        Cipher = new BlockCipheruwet(previousBlock, keyBytes);
                        pre = Cipher.encrypt();
                        cipherBuffer = XorByteArray(paddedBuffer, pre);
                        bw.Write(cipherBuffer);
                        Array.Copy(pre, previousBlock, blockSize);
                        break;
                    default:
                        break;
                }

                pos += blockSize;
            }

            // Body is written.

            // Close write handle
            bw.Close();
            fw.Close();

            // Close read handle
            br.Close();
            fr.Close();
        }

        /// <summary>
        /// Decrypt a given source file and save it to a given target file.
        /// </summary>
        /// <param name="sourceFileName">The filename of the source file. Presumed to exist.</param>
        /// <param name="destinationFileName">The filename of the target file. Will be overwritten.</param>
        /// <param name="key">The key to decrypt with.</param>
        public static void StartDecryption(String sourceFileName, String destinationFileName, String key)
        {
            // Auxiliary variables
            int readPos = 0; // Reading position
            Int64 originalFileSize = 0; // Original file size
            Int64 remainingBody = 0; // Bytes left to read
            Int32 blockSize = 0;
            byte cipherMode = 0;
            byte cr = Convert.ToByte('\r');
            byte lf = Convert.ToByte('\n');
            byte[] initializationVector;

            char[] keyChars = key.ToCharArray();
            byte[] keyBytes = new byte[key.Length];
            for (var i = 0; i < key.Length; ++i)
            {
                keyBytes[i] = Convert.ToByte(keyChars[i]);
            }

            // Open read handle. Treat all files as binary.
            FileStream fr = File.OpenRead(sourceFileName);
            BinaryReader br = new BinaryReader(fr);

            // Open write handle.
            FileStream fw = File.OpenWrite(destinationFileName);
            BinaryWriter bw = new BinaryWriter(fw);

            // Read header

            // 1. Original filesize
            originalFileSize = br.ReadInt64();
            readPos += sizeof(Int64);

            // 2. Block size
            blockSize = br.ReadInt32();
            readPos += sizeof(Int32);

            // 3. Cipher mode
            cipherMode = br.ReadByte();
            readPos += sizeof(byte);

            // 4. CRLF -- validate their existence
            if (br.ReadByte() != cr)
                throw new Exception("Invalid ciphertext header.");
            readPos += sizeof(byte);

            if (br.ReadByte() != lf)
                throw new Exception("Invalid ciphertext header.");
            readPos += sizeof(byte);

            // 5. Initialization vector
            initializationVector = br.ReadBytes(blockSize);
            readPos += blockSize;

            // 6. CRLF again -- validate their existence
            if (br.ReadByte() != cr)
                throw new Exception("Invalid ciphertext header.");
            readPos += sizeof(byte);

            if (br.ReadByte() != lf)
                throw new Exception("Invalid ciphertext header.");
            readPos += sizeof(byte);

            // We're done with the header, we can now proceed to the body.

            remainingBody = originalFileSize;
            byte[] previousBlock = initializationVector;

            while (readPos < fr.Length)
            {
                byte[] cipherBuffer = br.ReadBytes(blockSize);
                byte[] toWrite = new byte[blockSize];
                byte[] plainBuffer;
                byte[] preXor;
                BlockCipheruwet Cipher;

                // Decrypt the buffer and write to destination file
                switch (cipherMode)
                {
                    case ECB:
                        Cipher = new BlockCipheruwet(cipherBuffer, keyBytes);
                        plainBuffer = Cipher.decrypt();
                        toWrite = plainBuffer;
                        break;
                    case CBC:
                        Cipher = new BlockCipheruwet(cipherBuffer, keyBytes);
                        preXor = Cipher.decrypt();
                        plainBuffer = XorByteArray(preXor, previousBlock);
                        toWrite = plainBuffer;
                        previousBlock = cipherBuffer;
                        break;
                    case CFB:
                        Cipher = new BlockCipheruwet(previousBlock, keyBytes);
                        preXor = Cipher.encrypt();
                        plainBuffer = XorByteArray(preXor, cipherBuffer);
                        toWrite = plainBuffer;
                        previousBlock = cipherBuffer;
                        break;
                    case OFB:
                        Cipher = new BlockCipheruwet(previousBlock, keyBytes);
                        preXor = Cipher.encrypt();
                        plainBuffer = XorByteArray(preXor, cipherBuffer);
                        toWrite = plainBuffer;
                        previousBlock = preXor;
                        break;
                    default:
                        break;
                }

                if (remainingBody < blockSize)
                {
                    byte[] writeBuffer = new byte[remainingBody];
                    Array.Copy(toWrite, writeBuffer, (int)remainingBody);

                    bw.Write(writeBuffer);
                }
                else
                {
                    bw.Write(toWrite);
                }

                readPos += blockSize;
                remainingBody -= blockSize;
            }

            // Mode is read from the header of the file

            // Close write handle
            bw.Close();
            fw.Close();

            // Close read handle
            br.Close();
            fr.Close();
        }
    }
}
