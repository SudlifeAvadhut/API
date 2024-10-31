

            https://stackblitz.com/angular/jxxlggybaxo?file=src%2Fapp%2Fexpansion-steps-example.html




// Encrypty data using random generated IV algorithm


 public string EncryptData(string DecryptTxt, string key)
 {
     try
     {
         using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
         {
         
             aes.BlockSize = 128;
             aes.KeySize = 256;
             aes.Mode = CipherMode.CBC;
             aes.Padding = PaddingMode.PKCS7;

             byte[] IVBytes16Value = new byte[16];

             byte[] KeyArrBytes32Value = new byte[32];

             aes.Key = Encoding.UTF8.GetBytes(key.Substring(0, 32));

             aes.GenerateIV();

             ICryptoTransform encrypto = aes.CreateEncryptor(aes.Key, aes.IV);

             byte[] plainTextByte = ASCIIEncoding.UTF8.GetBytes(DecryptTxt);
             byte[] CipherText = encrypto.TransformFinalBlock(plainTextByte, 0, plainTextByte.Length);
             return Convert.ToBase64String(CipherText);
         }
     }
     catch (Exception ex)
     {
         throw;
     }
 }

=================================================================================================================================

// Decrypt data using random generated IV algorithm

 public string DecryptData(string EncryptedText, string key)
 {
     try
     {         

         using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
         {
             
             
             aes.BlockSize = 128;
             aes.KeySize = 256;

             aes.Mode = CipherMode.CBC;
             aes.Padding = PaddingMode.PKCS7;

             aes.Key = Encoding.UTF8.GetBytes(key.Substring(0, 32));
             byte[] iv = new byte[aes.BlockSize / 8];

             byte[] encryptedBytes = Convert.FromBase64CharArray(EncryptedText.ToCharArray(), 0, EncryptedText.Length);

             byte[] cipherText = new byte[encryptedBytes.Length - iv.Length];

             Array.Copy(encryptedBytes, iv, iv.Length);
             Array.Copy(encryptedBytes, iv.Length, cipherText, 0, cipherText.Length);
             aes.IV = iv;

             ICryptoTransform decrypto = aes.CreateDecryptor(aes.Key, aes.IV);


             byte[] decryptedData = decrypto.TransformFinalBlock(cipherText, 0, cipherText.Length);
             return ASCIIEncoding.UTF8.GetString(decryptedData);
         }
     }
     catch (Exception ex)
     {         
         throw;
     }
 }

