using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureTransfer
{
    class Program
    {
        private CngKey _aliceKey;
        private CngKey _bobKey;
        private byte[] _alicePubKeyBlob;
        private byte[] _bobPubKeyBlob;

        static async Task Main()
        {
            var p = new Program();
            await p.RunAsync();
            Console.ReadLine();
        }

        private async Task RunAsync()
        {
            // create all the keys
            // simulate aslices ending an enncypted message to bob
            // simulate bob recivinng and decyypting the alice'smesage
            try
            {
                CreateKeys();
                byte[] encrytpedData = await AliceSendsDataAsync("this is a secret message for Bob");
                await BobReceivesDataAsync(encrytpedData);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        private void CreateKeys()
        {       
            // create private and public keys for alice and bob
            _aliceKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP521);
            _bobKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP521);
            _alicePubKeyBlob = _aliceKey.Export(CngKeyBlobFormat.EccPublicBlob);
            _bobPubKeyBlob = _bobKey.Export(CngKeyBlobFormat.EccPublicBlob);
        }

        private async Task<byte[]> AliceSendsDataAsync(string message)
        {
            // convert supplied message to bytes stream
            Console.WriteLine($"Alice sends message: {message}");
            byte[] rawData = Encoding.UTF8.GetBytes(message);
            byte[] encryptedData = null;
 
            //start a class instance to help us do the EC Diffie-Hellman 521 algorithm
            //algorithm gives a way of create the same symmetric key, independently,
            //by alice and bob 
            //here it uses alice's keys and bib's public key
            using (var aliceAlgorithm = new ECDiffieHellmanCng(_aliceKey))
            using (CngKey bobPubKey = CngKey.Import(_bobPubKeyBlob,
                  CngKeyBlobFormat.EccPublicBlob))
            {
                // create a symmetric key using Elliptic-curve Diffie–Hellman
                byte[] symmKey = aliceAlgorithm.DeriveKeyMaterial(bobPubKey);
                Console.WriteLine("Alice creates this symmetric key with " +
                      $"Bobs public key information: { Convert.ToBase64String(symmKey)}");

                //the symmetric key is used to en-crypt the message using AES
                //we use AES to scramble the (encypt) the message
                using (var aes = new AesCryptoServiceProvider())
                {
                    aes.Key = symmKey;
                    aes.GenerateIV();
                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (var ms = new MemoryStream())
                    {
                        // create CryptoStream and encrypt data
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {

                            // write initialization vector not encrypted
                            await ms.WriteAsync(aes.IV, 0, aes.IV.Length);
                            await cs.WriteAsync(rawData, 0, rawData.Length);
                        }
                        encryptedData = ms.ToArray();
                    }
                    aes.Clear();
                }
            }
            Console.WriteLine($"Alice: message is encrypted: {Convert.ToBase64String(encryptedData)}"); ;
            Console.WriteLine();
            return encryptedData;
        }

        private async Task BobReceivesDataAsync(byte[] encryptedData)
        {
            Console.WriteLine("Bob receives encrypted data");
            byte[] rawData = null;

            var aes = new AesCryptoServiceProvider();

            int nBytes = aes.BlockSize >> 3;
            byte[] iv = new byte[nBytes];
            for (int i = 0; i < iv.Length; i++)
                iv[i] = encryptedData[i];

            //start a class instance to help us do the EC Diffie-Hellman 521 algorithm
            //algorithm gives a way of create the same symmetric key, independently,
            //by alice and bob 
            //here it uses bob's keys and alice's public key
            using (var bobAlgorithm = new ECDiffieHellmanCng(_bobKey))
            using (CngKey alicePubKey = CngKey.Import(_alicePubKeyBlob,
                  CngKeyBlobFormat.EccPublicBlob))
            {
                // create a symmetric key using alice's public key and bob's private key
                byte[] symmKey = bobAlgorithm.DeriveKeyMaterial(alicePubKey);
                Console.WriteLine("Bob creates this symmetric key with " +
                      $"Alices public key information: {Convert.ToBase64String(symmKey)}");
                
                
                // the symmetric key is used to de-crypt the message using AES
                aes.Key = symmKey;
                aes.IV = iv;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                using (MemoryStream ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    {
                        await cs.WriteAsync(encryptedData, nBytes, encryptedData.Length - nBytes);
                    }

                    rawData = ms.ToArray();

                    Console.WriteLine($"Bob decrypts message to: {Encoding.UTF8.GetString(rawData)}");
                }
                aes.Clear();
            }
        }
    }
}
