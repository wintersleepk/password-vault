#ifndef AUTH_H
#define AUTH_H

int generate_salt(char *salt,int len);
int sha256(const char *password,const char *salt,char *str, char outputbuffer[65]);
int sign_in(char *user_name);
int login(char *user_name);


#endif