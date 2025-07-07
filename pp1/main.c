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

#include "security.h"
#include "auth.h"
#include "vault.h"

#define RESET_TEXT "\033[0m"
#define RED_BOLD "\033[1;31m"
#define GREEN_BOLD "\033[1;32m"
#define green_text "\033[32m"
#define red_text "\033[31m"
#define cyan_text "\033[46m"
#define CYAN_BOLD "\033[1;46m"
/*============================
      🔐 PASSWORD VAULT     
============================
[1] ➕ Add New Entry
[2] 📄 View All Entries
[3] 🔍 Search by Service
[4] ✏️  Edit Entry
[5] 🗑️  Delete Entry
[6] 🚪 Exit
============================
Enter your choice: _*/


int menu(char *user_name){
     int choice;

     do {
        printf(RED_BOLD"=====================================\n");
        printf("      🔐 PASSWORD VAULT SYSTEM       \n");
        printf("=====================================\n");
        printf("[1] ➕ Add New Entry\n");
        printf("[2] 📄 View All Entries\n");
        printf("[3] 🔍 Search by Service\n");
        printf("[4] ✏️  Edit Entry\n");
        printf("[5] 🗑️  Delete Entry\n");
        printf("[6] 🚪 Exit\n");
        printf("=====================================\n"RESET_TEXT);
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar();

        switch(choice){
            case 1: vault_add(user_name); break;
            case 2: vault_view(user_name); break;
            case 3: vault_search(user_name); break;
            case 4: vault_edit(user_name); break;
            case 5: vault_delete(user_name); break;
            case 6: printf("\nLOGING-OUT >>>>> GOODBYE/-:"); break;
            default: printf("\nInvalid<<<<<"); break;
        }
     }
     while(choice!=6);
     return 0;
}

int main(){
    char user_name[100];
    char ch;
    
    printf("\n==== WELCOME TO THE PASSWORD VAULT ====\n");

    printf("\nARE YOU A NEW USER Y/N:");
    scanf(" %c",&ch);
    getchar();

    if ((ch=='n')|| (ch=='N')){

        if (!login(user_name)) {
        printf("Authentication failed.\n");

        // clean up even after failed login
        OPENSSL_cleanse(user_name, sizeof(user_name));
        return 1;
        }
    }
    else{
        sign_in(user_name);
    }
    
    menu(user_name);

    OPENSSL_cleanse(user_name, sizeof(user_name));
    printf("\nLOGGED OUT....");
    return 0;
}


