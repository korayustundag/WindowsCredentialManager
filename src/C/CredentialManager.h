#ifndef CREDENTIALMANAGER_H
#define CREDENTIALMANAGER_H

#include <windows.h>
#include <wincred.h>
#include <stdbool.h>

bool AddCredential(const wchar_t* target, const wchar_t* username, const wchar_t* password);
bool ReadCredential(const wchar_t* target, wchar_t** username, wchar_t** password);
bool DeleteCredential(const wchar_t* target);
bool ValidateCredential(const wchar_t* target, const wchar_t* username, const wchar_t* password);

#endif
