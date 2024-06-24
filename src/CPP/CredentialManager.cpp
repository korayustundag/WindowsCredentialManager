#include "CredentialManager.hpp"
#include <windows.h>
#include <wincred.h>
#include <iostream>

bool CredentialManager::AddCredential(const std::wstring& target, const std::wstring& username, const std::wstring& password)
{
    CREDENTIALW cred = { 0 };
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = const_cast<LPWSTR>(target.c_str());
    cred.UserName = const_cast<LPWSTR>(username.c_str());
    cred.CredentialBlobSize = (DWORD)(password.size() * sizeof(wchar_t));
    cred.CredentialBlob = (LPBYTE)password.c_str();
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

bool CredentialManager::ReadCredential(const std::wstring& target, std::wstring& username, std::wstring& password)
{
    PCREDENTIALW pcred;
    if (CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &pcred))
    {
        username = pcred->UserName;
        password.assign((wchar_t*)pcred->CredentialBlob, pcred->CredentialBlobSize / sizeof(wchar_t));
        CredFree(pcred);
        return true;
    }
    else
    {
        PrintError(L"CredReadW");
        return false;
    }
}

bool CredentialManager::DeleteCredential(const std::wstring& target)
{
    if (CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0))
    {
        return true;
    }
    else
    {
        PrintError(L"CredDeleteW");
        return false;
    }
}

bool CredentialManager::ValidateCredential(const std::wstring& target, const std::wstring& username, const std::wstring& password)
{
    std::wstring storedUsername, storedPassword;
    if (ReadCredential(target, storedUsername, storedPassword))
    {
        return storedUsername == username && storedPassword == password;
    }
    return false;
}

void CredentialManager::PrintError(const std::wstring& functionName)
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
    std::wcerr << L"Error in " << functionName << L": " << (LPWSTR)errorMsg << std::endl;
    LocalFree(errorMsg);
}
