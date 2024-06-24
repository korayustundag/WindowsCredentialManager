#include "CredentialManager.h"
#include <stdio.h>

int main()
{
    const wchar_t* target = L"MyApp";
    const wchar_t* username = L"user";
    const wchar_t* password = L"password";

    if (AddCredential(target, username, password))
    {
        wprintf(L"Credential added successfully.\n");
    }

    wchar_t* readUsername = NULL;
    wchar_t* readPassword = NULL;
    if (ReadCredential(target, &readUsername, &readPassword))
    {
        wprintf(L"Read credential successfully.\n");
        wprintf(L"Username: %s\n", readUsername);
        wprintf(L"Password: %s\n", readPassword);
        free(readUsername);
        free(readPassword);
    }

    if (ValidateCredential(target, username, password))
    {
        wprintf(L"Credential validation successful.\n");
    }
    else
    {
        wprintf(L"Credential validation failed.\n");
    }

    if (DeleteCredential(target))
    {
        wprintf(L"Credential deleted successfully.\n");
    }

    return 0;
}
