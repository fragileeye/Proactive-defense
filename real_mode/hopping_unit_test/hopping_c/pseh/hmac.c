#include <linux/string.h>
#include "hmac.h"
#include "md5.h"
#include "sha256.h"

void hmac_md5(unsigned char *key, int key_len,
    unsigned char *text, int text_len, unsigned char *hmac)
{
    MD5_CTX context;
	unsigned char k_ipad[KEY_IOPAD_SIZE] = {0};   
	unsigned char k_opad[KEY_IOPAD_SIZE] = {0};  
    int i;

    memcpy( k_ipad, key, key_len);
    memcpy( k_opad, key, key_len);
    
    for (i = 0; i < KEY_IOPAD_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    MD5Init(&context);                  
    MD5Update(&context, k_ipad, KEY_IOPAD_SIZE);     
    MD5Update(&context, (unsigned char*)text, text_len); 
    MD5Final(hmac, &context);            
    

    MD5Init(&context);                  
    MD5Update(&context, k_opad, KEY_IOPAD_SIZE);   
    MD5Update(&context, hmac, MD5_DIGEST_SIZE);     
    MD5Final(hmac, &context);       
}

void hmac_sha256(unsigned char *key, int key_len,
    unsigned char *text, int text_len, unsigned char *hmac) {
    SHA256_State context;
    unsigned char k_ipad[KEY_IOPAD_SIZE] = {0};    
    unsigned char k_opad[KEY_IOPAD_SIZE] = {0};    
    int i;

    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

   
    for (i = 0; i < KEY_IOPAD_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }


    SHA256_Init(&context);                   
    SHA256_Bytes(&context, k_ipad, KEY_IOPAD_SIZE);    
    SHA256_Bytes(&context, text, text_len); 
    SHA256_Final(&context, hmac);            

    SHA256_Init(&context);                  
    SHA256_Bytes(&context, k_opad, KEY_IOPAD_SIZE);    
    SHA256_Bytes(&context, hmac, SHA256_DIGEST_SIZE);     
    SHA256_Final(&context, hmac);         
}
