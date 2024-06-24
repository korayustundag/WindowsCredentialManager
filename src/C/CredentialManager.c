#include "CredentialManager.h"
#include <stdio.h>
#include <stdlib.h>

void PrintError(const wchar_t* functionName)
{
    DWORD errorCode = GetLastError();
    LPVOID errorMsg;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        0,
        (LPWSTR)&errorMsg,
        0,
        NULL);
    wprintf(L"Error in %s: %s\n", functionName, (LPWSTR)errorMsg);
    LocalFree(errorMsg);
}

bool AddCredential(const wchar_t* target, const wchar_t* username, const wchar_t* password)
{
    CREDENTIALW cred = { 0 };
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = (LPWSTR)target;
    cred.UserName = (LPWSTR)username;
    cred.CredentialBlobSize = (DWORD)(wcslen(password) * sizeof(wchar_t));
    cred.CredentialBlob = (LPBYTE)password;
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

    if (CredWriteW(&cred, 0))
    {
        return true;
    }
    else
    {
        PrintError(L"CredWriteW");
        return false;
    }
}

bool ReadCredential(const wchar_t* target, wchar_t** username, wchar_t** password)
{
    PCREDENTIALW pcred;
    if (CredReadW(target, CRED_TYPE_GENERIC, 0, &pcred))
    {
        *username = _wcsdup(pcred->UserName);
        *password = (wchar_t*)malloc(pcred->CredentialBlobSize + sizeof(wchar_t));
        if (*password)
        {
            memcpy(*password, pcred->CredentialBlob, pcred->CredentialBlobSize);
            (*password)[pcred->CredentialBlobSize / sizeof(wchar_t)] = L'\0';
        }
        CredFree(pcred);
        return true;
    }
    else
    {
        PrintError(L"CredReadW");
        return false;
    }
}

bool DeleteCredential(const wchar_t* target)
{
    if (CredDeleteW(target, CRED_TYPE_GENERIC, 0))
    {
        return true;
    }
    else
    {
        PrintError(L"CredDeleteW");
        return false;
    }
}

bool ValidateCredential(const wchar_t* target, const wchar_t* username, const wchar_t* password)
{
    wchar_t* storedUsername = NULL;
    wchar_t* storedPassword = NULL;
    bool result = false;

    if (ReadCredential(target, &storedUsername, &storedPassword))
    {
        if (wcscmp(storedUsername, username) == 0 && wcscmp(storedPassword, password) == 0)
        {
            result = true;
        }
        free(storedUsername);
        free(storedPassword);
    }

    return result;
}
