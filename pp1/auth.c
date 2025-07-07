#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <ctype.h>
#include "vault.h"
#include "security.h"

int generate_salt(char *salt,int len){
    const char charset[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0987654321";
    srand(time(NULL));  
    for (int i=0; i<len; i++){
        salt[i]=charset[rand()%(sizeof(charset)-1)];
    } 
    
    salt[len]='\0';
    return 1;  // success 
}

int sha256(const char *password, const char *salt,char *salted, char outputbuffer[65]){
    int len=SHA256_DIGEST_LENGTH;
    unsigned char hash[len];
    sprintf(salted,"%s:%s",salt,password);
    SHA256((const unsigned char *)salted,strlen(salted),hash);
    for (int i=0; i<len; i++){
        sprintf(outputbuffer + (i*2),"%02x",hash[i]);
    }

    outputbuffer[64]='\0';
    return 1; //success
}


int sign_in(char *user_name){

    printf("\n=====SIGN-IN MENU====\n");

    FILE *fp;

    fp=fopen("newstorage.txt","a");

    printf("\n=====WELCOME TO SIGN-IN MENU====\n");

    printf("\nEnter the user name:");
    scanf(" %[^\n]",user_name);
    getchar();

    char password[100];
    do {
        printf("\nSet your password: ");
        scanf(" %[^\n]", password);
        getchar();
    } while (!pwd_checker(password));

    char salt[17];
    char hash[65],salted[100];

    printf("\nstarting salting.....");
    generate_salt(salt,16);
    printf("\nsalting done..");

    printf("\nstarting the hashing.....");
    sha256(password,salt,salted,hash);
    printf("\nhashing done..");

    printf("\nprinting to the file...");


    fprintf(fp,"%s:%s:%s\n",user_name,salt,hash);
    printf("\nprinting done..");

    OPENSSL_cleanse(password, sizeof(password));
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(salted, sizeof(salted));
    OPENSSL_cleanse(hash, sizeof(hash));

    fclose(fp);
    return 1;

}

int login(char *user_name){
    
    printf("\n====LOGIN MENU====\n");

    FILE *fp;

    fp=fopen("newstorage.txt","r");

    if (fp == NULL) {
    perror("Error opening file");
    return 1;
    }

    char data[200];
    char password[100];
    char salted[100],hash[65];
    int found=0;

    printf("\nEnter the user name:");
    scanf(" %[^\n]",user_name);
    getchar();

    printf("\nEnter the password:");
    scanf(" %[^\n]",password);
    getchar();

    printf("\nchecking..");
    

    while((fgets(data,sizeof(data),fp))!= NULL){
        data[strcspn(data,"\n")]='\0';
        char *user=strtok(data,":");
        char *salt=strtok(NULL,":");
        char *pass=strtok(NULL,"\n");

        if (!user || !salt || !pass) {
            printf("\nMalformed entry in file: skipping line.");
            continue;
        }

        if ((strcmp(user,user_name))==0){
            

            sha256(password,salt,salted,hash);

            if ((strcmp(hash,pass))==0){
            printf("\nWelcome %s",user_name);
            found=1;
            
            break;

            }
            else{
                printf("\nInvalid password");
                found=1;
                continue;
            }
        
            

        }
        else {
            printf("\nInvalid user name");
            found =1;

            continue;
        }
        
    }

    OPENSSL_cleanse(password, sizeof(password));
    OPENSSL_cleanse(salted, sizeof(salted));
    OPENSSL_cleanse(hash, sizeof(hash));
    
    fclose(fp);

    if(!found){
        printf("\nuser not found..");
        return 0;
    }
    else{
        return 1;
    }


    
}