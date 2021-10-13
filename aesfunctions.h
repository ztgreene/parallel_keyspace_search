#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

/*****************************************************************************
 * Function: aes_init
 * 
 * Initialises the aes encryption struct using the proveded key, key length,
 * and the EVP_aes_256_cbc() mode.
 * 
 * Parameters: 
 *     unsigned char *key_data - Pointer to the Key
 *     int key_data_len - The length of the key 
 *     EVP_CIPHER_CTX *e_ctx - Pointer to the encryption device
 *     EVP_CIPHER_CTX *d_ctx - Pointer to the decryption device
 * 
 * Returns: 0 on Success (TODO: additional error checking)
 * ***************************************************************************/
int
aes_init (unsigned char *key_data, int key_data_len, EVP_CIPHER_CTX * e_ctx,
	  EVP_CIPHER_CTX * d_ctx)
{

  int i;
  unsigned char key[32], iv[32];
  //Some robust programming to start with
  //Only use most significant 32 bytes of data if > 32 bytes
  if (key_data_len > 32)
    key_data_len = 32;

  //In a real-word solution, the key would be filled with a random
  //stream of bytes - we are taking a shortcut because encryption
  //is not the focus of this unit.
  for (i = 0; i < key_data_len; i++)
    {
      key[i] = key_data[i];
      iv[i] = key_data[i];
    }
  //Pad out to 32 bytes if key < 32 bytes
  for (i = key_data_len; i < 32; i++)
    {
      key[i] = 0;
      iv[i] = 0;
    }
  //Create and initialize the encryption device.
  EVP_CIPHER_CTX_init (e_ctx);
  EVP_EncryptInit_ex (e_ctx, EVP_aes_256_cbc (), NULL, key, iv);
  EVP_CIPHER_CTX_init (d_ctx);
  EVP_DecryptInit_ex (d_ctx, EVP_aes_256_cbc (), NULL, key, iv);

  return 0;
}

/*
 * Decrypt *len bytes of ciphertext
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *
aes_decrypt (EVP_CIPHER_CTX * e, unsigned char *ciphertext, int *len)
{
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc(p_len);

  EVP_DecryptInit_ex (e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate (e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex (e, plaintext + p_len, &f_len);

  return plaintext;
}
