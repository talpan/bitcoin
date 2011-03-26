#ifndef __CRYPTER_H__
#define __CRYPTER_H__

class CCrypter
{
protected:
    EVP_CIPHER_CTX e_ctx;
    EVP_CIPHER_CTX d_ctx;

public:
    bool SetKey(const unsigned char *keyData, int keyData_len,
                const unsigned char *salt)
    {
        int nrounds = 1000;
        unsigned char key[32], iv[32];
  
        int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt,
                               keyData, keyData_len, nrounds, key, iv);
        if (i != 32)
            return false;

        EVP_CIPHER_CTX_init(&e_ctx);
        EVP_EncryptInit_ex(&e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
        EVP_CIPHER_CTX_init(&d_ctx);
        EVP_DecryptInit_ex(&d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

        return true;
    }

    vector<unsigned char> Encrypt(vector<unsigned char> vchPlaintext)
    {
      // max ciphertext len for a n bytes of plaintext is
      // n + AES_BLOCK_SIZE - 1 bytes
      int len = vchPlaintext.size();
      int c_len = len + AES_BLOCK_SIZE, f_len = 0;
      vector<unsigned char> vchCiphertext(c_len);

      EVP_EncryptInit_ex(&e_ctx, NULL, NULL, NULL, NULL);
      EVP_EncryptUpdate(&e_ctx, &vchCiphertext[0], &c_len,
                        &vchPlaintext[0], len);
      EVP_EncryptFinal_ex(&e_ctx, (&vchCiphertext[0])+c_len, &f_len);

      vchCiphertext.resize(c_len + f_len);
      return vchCiphertext;
    }

    vector<unsigned char> Decrypt(vector<unsigned char> vchCiphertext)
    {
      // plaintext will always be equal to or lesser than length of ciphertext
      int len = vchCiphertext.size();
      int p_len = len, f_len = 0;
      vector<unsigned char> vchPlaintext(p_len);
  
      EVP_DecryptInit_ex(&d_ctx, NULL, NULL, NULL, NULL);
      EVP_DecryptUpdate(&d_ctx, &vchPlaintext[0], &p_len,
                        &vchCiphertext[0], len);
      EVP_DecryptFinal_ex(&d_ctx, (&vchPlaintext[0])+p_len, &f_len);

      vchPlaintext.resize(p_len + f_len);
      return vchPlaintext;
    }
};

#endif /* __CRYPTER_H__ */
