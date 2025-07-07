#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h> 
#include <openssl/crypto.h>
#include <ctype.h>
#include "auth.h"
#include "vault.h"


int encrypt(unsigned char *plain_text,int plain_text_len,unsigned char *key,unsigned char *iv,unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    //create and initialize the text
    if( !(ctx=EVP_CIPHER_CTX_new())){
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // initialize the  encryption process 
    if(1!= EVP_EncryptInit_ex(ctx,EVP_aes_256_cbc(),NULL,key,iv)){
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    //encrypt the text
    if(1!=EVP_EncryptUpdate(ctx,ciphertext,&len,plain_text,plain_text_len)){
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len=len;
    // finalize the encryption
    if(1!=EVP_EncryptFinal_ex(ctx,ciphertext+len,&len)){
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len+=len;

    EVP_CIPHER_CTX_free(ctx);

    OPENSSL_cleanse(plain_text, plain_text_len);
    return ciphertext_len;
    
}

void hex_to_bytes(const char *hex, unsigned char *bytes, int len) {
    for (int i = 0; i < len; i++) {
        sscanf(hex + 2*i, "%2hhx", &bytes[i]);
    }
}

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext,int ciphertext_len,unsigned char *key,unsigned char *iv,unsigned char *plaintext){

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    ctx=EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_cbc(),NULL,key,iv)) 
        handle_errors();

    if (1!=EVP_DecryptUpdate(ctx,plaintext,&len,ciphertext,ciphertext_len))
        handle_errors();
    plaintext_len=len;

    if(1!=EVP_DecryptFinal_ex(ctx,plaintext+len,&len))
        handle_errors();
    
    plaintext_len+=len;

    EVP_CIPHER_CTX_free(ctx);

    OPENSSL_cleanse(ciphertext, ciphertext_len);
    return plaintext_len;
}

int pwd_checker(char *password){
    //password checker
    int upper,lower,digit,special;
    upper=0;
    lower=0;
    digit=0;
    special=0;
    int len =strlen(password);

    if (len<8){
        printf("\n[X] PASSWORD NOT LONG ENOUGH..!!");
        return 0;
    }
    else{
        for (int i=0; i<len; i++){
            if (isupper(password[i])){
                upper++;
            }
            else if (islower(password[i])){
                lower++;
            }
            else if (isdigit(password[i])){
                digit++;
            }
            else if (ispunct(password[i])){
                special++;
            }
        }
    }

    OPENSSL_cleanse(password, len);
    
    if (upper>= 1 && lower >=1 && digit >= 1 && special >= 1 ){
        return 1;
    }
    else{
        printf("\nPASSWORD NOT STRONG ENOUGH..");
        return 0;
    }
}
