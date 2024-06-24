#include "CredentialManager.hpp"
#include <iostream>

int main()
{
    CredentialManager credManager;
    std::wstring target = L"MyApp";
    std::wstring username = L"user";
    std::wstring password = L"password";

    if (credManager.AddCredential(target, username, password))
    {
        std::wcout << L"Credential added successfully." << std::endl;
    }

    std::wstring readUsername, readPassword;
    if (credManager.ReadCredential(target, readUsername, readPassword))
    {
        std::wcout << L"Read credential successfully." << std::endl;
        std::wcout << L"Username: " << readUsername << std::endl;
        std::wcout << L"Password: " << readPassword << std::endl;
    }

    if (credManager.ValidateCredential(target, username, password))
    {
        std::wcout << L"Credential validation successful." << std::endl;
    }
    else
    {
        std::wcout << L"Credential validation failed." << std::endl;
    }

    if (credManager.DeleteCredential(target))
    {
        std::wcout << L"Credential deleted successfully." << std::endl;
    }
}
