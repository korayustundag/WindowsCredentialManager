#ifndef CREDENTIALMANAGER_H
#define CREDENTIALMANAGER_H

#include <string>

class CredentialManager
{
public:
    bool AddCredential(const std::wstring& target, const std::wstring& username, const std::wstring& password);
    bool ReadCredential(const std::wstring& target, std::wstring& username, std::wstring& password);
    bool DeleteCredential(const std::wstring& target);
    bool ValidateCredential(const std::wstring& target, const std::wstring& username, const std::wstring& password);

private:
    void PrintError(const std::wstring& functionName);
};

#endif
