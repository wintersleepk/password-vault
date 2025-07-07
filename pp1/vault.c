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
#include "security.h"


int vault_add(char *user_name) {
    FILE *fp;

    char filename[256];
    char service[200], username[200], pass[200];
    char vault_entry[1000];
    
    

    printf("\nthe username is :%s\n",user_name);
    snprintf(filename,sizeof(filename),"vault_%s.dat",user_name);

    

    fp = fopen(filename, "ab"); // text mode because we'll write hex
    if (!fp) {
        perror("Unable to open vault file");
        return 1;
    }

    printf("\nEnter the service: ");
    scanf(" %[^\n]", service);
    getchar();

    printf("\nEnter the username: ");
    scanf(" %[^\n]", username);
    getchar();

    printf("\nEnter the password: ");
    scanf(" %[^\n]", pass);
    getchar();

    snprintf(vault_entry, sizeof(vault_entry), "SERVICE: %s\nUSERNAME: %s\nPASSWORD: %s\n", service, username, pass);

    unsigned char key[32] = "01234567890123456789012345678901";
    unsigned char iv[16];
    unsigned char output[512];
    int output_len;

    // Generate a random IV
    if (!RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "IV generation failed\n");
        fclose(fp);
        return 1;
    }

    output_len = encrypt((unsigned char *)vault_entry, strlen(vault_entry), key, iv, output);

    // Convert IV and ciphertext to hex
    char iv_hex[33], cipher_hex[output_len * 2 + 1];
    for (int i = 0; i < 16; i++) sprintf(iv_hex + i * 2, "%02x", iv[i]);
    for (int i = 0; i < output_len; i++) sprintf(cipher_hex + i * 2, "%02x", output[i]);

    fprintf(fp, "%s:%s\n", iv_hex, cipher_hex);
    fclose(fp);

    printf("\n🔒 Vault entry added.\n");

    OPENSSL_cleanse(pass, sizeof(pass)); 
    OPENSSL_cleanse(username, sizeof(username));
    OPENSSL_cleanse(service, sizeof(service));
    OPENSSL_cleanse(vault_entry, sizeof(vault_entry));
    OPENSSL_cleanse(output, sizeof(output));
    OPENSSL_cleanse(key, sizeof(key));
    return 0;
}

int vault_view(char *user_name){

    printf("\n=====VIEWING-ALL ENTRIES=====\n");

    FILE *fp;

    char filename[256];
    
    

    printf("\nthe username is :%s\n",user_name);
    snprintf(filename,sizeof(filename),"vault_%s.dat",user_name);

    fp=fopen(filename,"rb");

    if (!fp){
        printf("\nCould not open the vault file...");
        return 1;
    }

    char line[1000];
    int line_num=1;
    
    while(fgets(line,sizeof(line),fp)){
        line[strcspn(line,"\n")]='\0';
        char *iv_hex=strtok(line,":");
        char *cipher_hex=strtok(NULL,"\n");

        if (!iv_hex || !cipher_hex) {
            printf("Skipping line %d (corrupted)\n", line_num++);
            continue;
        }

        unsigned char key[32]="01234567890123456789012345678901";
        unsigned char iv[16];
        unsigned char output[1000];
        int output_len;
        unsigned char ciphertext[256];
        int cipher_len=strlen(cipher_hex)/2;

        hex_to_bytes(iv_hex,iv,16);
        hex_to_bytes(cipher_hex,ciphertext,cipher_len);

        output_len=decrypt(ciphertext,cipher_len,key,iv,output);
        output[output_len]='\0';

        printf("`.`-%d.%s\n",line_num++,output);

        OPENSSL_cleanse(output, sizeof(output));
        OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
        OPENSSL_cleanse(key, sizeof(key));
    }
    fclose(fp);


    return 0;

}

int vault_search(char *user_name){
    printf("\n=====SEARCHING-ENTRY MENU=====\n");

    FILE *fp;

    char filename[256];
    
    

    printf("\nthe username is :%s\n",user_name);
    snprintf(filename,sizeof(filename),"vault_%s.dat",user_name);
    

    fp=fopen(filename,"rb");

    if (!fp) {
        perror("\n[!] Error opening vault file");
        return 1;
    }
    
    char data[1000];
    char search_service[100];
    int found=0;

    printf("\nENTER THE SERVICE WANT TO SEARCH:");
    scanf(" %[^\n]",search_service);
    getchar();

    while(fgets(data,sizeof(data),fp)!=NULL){
        data[strcspn(data,"\n")]='\0';

        char *iv_hex=strtok(data,":");
        char *cipher_hex=strtok(NULL,"\n");

        if (!iv_hex || !cipher_hex) {
            fprintf(stderr, "[!] Skipping malformed line.\n");
            continue;
        }

        unsigned char key[32]="01234567890123456789012345678901";
        unsigned char iv[16];
        unsigned char output[1024];
        int cipher_len=strlen(cipher_hex)/2;
        int output_len;
        unsigned char ciphertext[1024];

        hex_to_bytes(iv_hex,iv,16);
        hex_to_bytes(cipher_hex,ciphertext,cipher_len);

        output_len=decrypt(ciphertext,cipher_len,key,iv,output);
        if (output_len <= 0) {
            fprintf(stderr, "[!] Decryption failed.\n");
            continue;
        }
        output[output_len]='\0';

        if (strstr((char *)output,search_service)){
            printf("\nFOUND: %s\n",output);
            found=1;
            return 1;
        }
        OPENSSL_cleanse(output, sizeof(output));
        OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
        OPENSSL_cleanse(key, sizeof(key));
        OPENSSL_cleanse(search_service, sizeof(search_service));


    }
    fclose(fp);

    if (!found){
        printf("\n[x]! No matching entry found");
        return 0;
    }
    
    return found;
    
}

int vault_edit(char *user_name){
     printf("\n=====EDITING-ENTRY MENU=====\n");

    FILE *fp,*fm;

    char filename[256];
    
    

    printf("\nthe username is :%s\n",user_name);
    snprintf(filename,sizeof(filename),"vault_%s.dat",user_name);

    fp=fopen(filename,"rb");
    fm=fopen("temp.dat","wb");

    if (!fp || !fm) {
        perror("\n[!] Error opening vault file");
        return 1;
    }
    
    char data[1000];
    char search_service[100];
    int found=0;

    printf("\nENTER THE SERVICE WANT TO EDIT:");
    scanf(" %[^\n]",search_service);
    getchar();

    while(fgets(data,sizeof(data),fp)!=NULL){
        data[strcspn(data,"\n")]='\0';

        char *iv_hex=strtok(data,":");
        char *ciphertext_hex=strtok(NULL,"\n");

        if (!iv_hex || !ciphertext_hex) {
            fprintf(stderr, "[!] Skipping malformed line.\n");
            continue;
        }

        unsigned char key[32]="01234567890123456789012345678901";
        unsigned char iv[16];
        unsigned char output[1024];
        int ciphertext_len=strlen(ciphertext_hex)/2;
        int output_len;
        unsigned char ciphertext[1024];
        char service[100];
        char username[100],pass[100];
        char new_entry[1024];

        hex_to_bytes(iv_hex,iv,16);
        hex_to_bytes(ciphertext_hex,ciphertext,ciphertext_len);

        output_len=decrypt(ciphertext,ciphertext_len,key,iv,output);
        if (output_len <= 0) {
            fprintf(stderr, "[!] Decryption failed.\n");
            continue;
        }
        output[output_len]='\0';

        if (strstr((char *)output,search_service)){
            printf("\nFOUND: %s\n",output);
            found=1;

            unsigned char cipher[1024];
            int cipher_len;
            unsigned char new_iv[16];
            char new_iv_hex[33];



            printf("\nEDITING >>>>>>");
            printf("\nTAKING NEW ENTRIES>>>>");
            
            printf("\nENTER THE SERVICE:");
            scanf(" %[^\n]",service);
            getchar();

            printf("\nENTER THE USERNAME:");
            scanf(" %[^\n]",username);
            getchar();

            printf("\nENTER THE PASSWORD:");
            scanf(" %[^\n]",pass);
            getchar();

            snprintf(new_entry,sizeof(new_entry),"SERVICE: %s\nUSERNAME: %s\nPASSWORD: %s\n",service,username,pass);

            if (!RAND_bytes(new_iv,sizeof(new_iv))){
                fprintf(stderr,"IV generation failed\n");
                fclose(fp);
                fclose(fm);
                return 1;
            }

            cipher_len=encrypt(new_entry,strlen(new_entry),key,new_iv,cipher);
            

            

            char cipher_hex[cipher_len*2+1];
            for (int i=0; i<cipher_len; i++){
                sprintf(cipher_hex+i*2,"%02x",cipher[i]);
            }
            for (int i=0; i<16; i++){
                sprintf(new_iv_hex+i*2,"%02x",new_iv[i]);
            }

            fprintf(fm, "%s:%s\n", new_iv_hex, cipher_hex);

            OPENSSL_cleanse(cipher, sizeof(cipher));
            
        }
        else{
            fprintf(fm,"%s:%s\n",iv_hex,ciphertext_hex);
        }
        OPENSSL_cleanse(service, sizeof(service));
        OPENSSL_cleanse(username, sizeof(username));
        OPENSSL_cleanse(pass, sizeof(pass));
        OPENSSL_cleanse(new_entry, sizeof(new_entry));
        
        OPENSSL_cleanse(key, sizeof(key));



    }
    

    fclose(fp);
    fclose(fm);

    remove(filename);
    rename("temp.dat",filename);
    printf("\n[✓] DONE...");
    
    if (!found){
        printf("\n[x]! No matching entry found");
        return 0;
    }
    else{
        printf("\n[✓]Vault entry deleted successfully.\n");
        return 1;
    }

}

int vault_delete(char *user_name){
     printf("\n=====DELETING-ENTRY MENU=====\n");

    FILE *fp,*fm;

    char filename[256];
    
    

    printf("\nthe username is :%s\n",user_name);
    snprintf(filename,sizeof(filename),"vault_%s.dat",user_name);

    fp=fopen(filename,"rb");
    fm=fopen("temp.dat","wb");

    if (!fp || !fm) {
        perror("\n[!] Error opening vault file");
        return 1;
    }
    
    char data[1000];
    char search_service[100];
    int found=0;

    printf("\nENTER THE SERVICE WANT TO DELETE:");
    scanf(" %[^\n]",search_service);
    getchar();

    while(fgets(data,sizeof(data),fp)!=NULL){
        data[strcspn(data,"\n")]='\0';

        char *iv_hex=strtok(data,":");
        char *ciphertext_hex=strtok(NULL,"\n");

        if (!iv_hex || !ciphertext_hex) {
            fprintf(stderr, "[!] Skipping malformed line.\n");
            continue;
        }

        unsigned char key[32]="01234567890123456789012345678901";
        unsigned char iv[16];
        unsigned char output[1024];
        int ciphertext_len=strlen(ciphertext_hex)/2;
        int output_len;
        unsigned char ciphertext[1024];
        

        hex_to_bytes(iv_hex,iv,16);
        hex_to_bytes(ciphertext_hex,ciphertext,ciphertext_len);

        output_len=decrypt(ciphertext,ciphertext_len,key,iv,output);
        if (output_len <= 0) {
            fprintf(stderr, "[!] Decryption failed.\n");
            continue;
        }
        output[output_len]='\0';

        if (strstr((char *)output,search_service)){
            printf("\nFOUND: %s\n",output);
            found=1;

            printf("\nDELETING >>>>>>");
            continue;
        
        }
        else{
            fprintf(fm,"%s:%s\n",iv_hex,ciphertext_hex);
        }
        OPENSSL_cleanse(output, sizeof(output));
        OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
        OPENSSL_cleanse(search_service, sizeof(search_service));
        OPENSSL_cleanse(key, sizeof(key));



    }
    

    fclose(fp);
    fclose(fm);

    remove(filename);
    rename("temp.dat",filename);
    printf("\n[✓] DONE...");
    
    if (!found){
        printf("\n[x]! No matching entry found");
        return 0;
    }
    else{
        printf("\n[✓]Vault entry deleted successfully.\n");
        return 1;
    }

}
