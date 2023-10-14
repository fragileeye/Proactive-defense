#ifndef _CIPHER_HMAC_ALL_H
#define _CIPHER_HMAC_ALL_H

#define SHA256_DIGEST_SIZE  32
#define    MD5_DIGEST_SIZE  16
#define		KEY_IOPAD_SIZE	64
#define	 KEY_IOPAD_SIZE128  128

void hmac_md5(unsigned char *key, int key_len,
        unsigned char *text, int text_len, unsigned char *hmac);
  
void hmac_sha256(unsigned char *key, int key_len,
        unsigned char *text, int text_len, unsigned char *hmac);
#endif
