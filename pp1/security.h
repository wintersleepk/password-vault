#ifndef SECURITY_H
#define SECURITY_H

int encrypt(unsigned char *plain_text,int plain_text_len,unsigned char *key,unsigned char *iv,unsigned char *ciphertext);
void hex_to_bytes(const char *hex, unsigned char *bytes, int len);
void handle_errors();
int decrypt(unsigned char *ciphertext,int ciphertext_len,unsigned char *key,unsigned char *iv,unsigned char *plaintext);
int pwd_checker(char *password);

#endif