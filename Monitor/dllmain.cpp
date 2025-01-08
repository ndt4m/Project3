// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>
#include <Windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <DbgHelp.h>
#include "detours.h"
#include <vector>
#include <string>
#include <map>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Crypt32.lib")


// Function pointer declarations for advapi32.dll
BOOL(WINAPI* CryptAcquireContextAActual)(HCRYPTPROV* phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags) = CryptAcquireContextA;
BOOL(WINAPI* EncryptFileAActual)(LPCSTR lpFileName) = EncryptFileA;
BOOL(WINAPI* CryptEncryptActual)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen) = CryptEncrypt;
BOOL(WINAPI* CryptDecryptActual)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen) = CryptDecrypt;
BOOL(WINAPI* CryptCreateHashActual)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash) = CryptCreateHash;
BOOL(WINAPI* CryptHashDataActual)(HCRYPTHASH hHash, const BYTE* pbData, DWORD dwDataLen, DWORD dwFlags) = CryptHashData;
BOOL(WINAPI* CryptDeriveKeyActual)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY* phKey) = CryptDeriveKey;
BOOL(WINAPI* CryptSetKeyParamActual)(HCRYPTKEY hKey, DWORD dwParam, const BYTE* pbData, DWORD dwFlags) = CryptSetKeyParam;
BOOL(WINAPI* CryptGetHashParamActual)(HCRYPTHASH hHash, DWORD dwParam, BYTE* pbData, DWORD* pdwDataLen, DWORD dwFlags) = CryptGetHashParam;
BOOL(WINAPI* CryptDestroyKeyActual)(HCRYPTKEY hKey) = CryptDestroyKey;
BOOL(WINAPI* CryptGenRandomActual)(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer) = CryptGenRandom;
BOOL(WINAPI* DecryptFileAActual)(LPCSTR lpFileName, DWORD dwFlags) = DecryptFileA;

// Function pointer declarations for kernel32.dll
HANDLE(WINAPI* CreateFileAActual)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileA;
BOOL(WINAPI* ReadFileActual)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) = ReadFile;
BOOL(WINAPI* WriteFileActual)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped
    ) = WriteFile;
DWORD(WINAPI* GetLogicalDrivesActual)(void) = GetLogicalDrives;
UINT(WINAPI* GetDriveTypeAActual)(LPCSTR lpRootPathName) = GetDriveTypeA;
BOOL(WINAPI* EnumSystemLocalesAActual)(LOCALE_ENUMPROCA lpLocaleEnumProcEx, DWORD dwFlags) = EnumSystemLocalesA;

// Function pointer declarations for crypt32.dll
BOOL(WINAPI* CryptStringToBinaryAActual)(LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags) = CryptStringToBinaryA;
BOOL(WINAPI* CryptBinaryToStringAActual)(const BYTE* pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD* pcchString) = CryptBinaryToStringA;
BOOL(WINAPI* CryptReleaseContextActual)(HCRYPTPROV hProv, DWORD dwFlags) = CryptReleaseContext;
BOOL(WINAPI* CryptDestroyHashActual)(HCRYPTHASH hHash) = CryptDestroyHash;
BOOL(WINAPI* CryptProtectDataActual)(DATA_BLOB* pDataIn, LPCWSTR szDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut) = CryptProtectData;


struct LogEntry {
    std::string apiName;
    std::string pre_call_parameters;
    std::string post_call_parameters;
    std::string result;

    std::string toJSON() const {
        std::ostringstream json;
        json << "{";
        json << "\"apiName\": \"" << apiName << "\", ";
        json << "\"pre_call_parameters\": " << pre_call_parameters << ", ";
        json << "\"post_call_parameters\": " << post_call_parameters << ", ";
        json << "\"result\": " << result;
        json << "}";
        return json.str();
    }
};

BOOL Hook_CryptAcquireContextA(HCRYPTPROV* phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags) {
    LogEntry logEntry;
    logEntry.apiName = "CryptAcquireContextA";

    // Pre-call parameter logging
    std::ostringstream preCall;
    if (phProv) {
        preCall << "{\"phProv\": \"0x";
        preCall << std::hex << phProv;
        preCall << "=";
        preCall << "0x" << std::hex << *reinterpret_cast<uint64_t*>(phProv);
        preCall << "\"";
    }
    else {
        preCall << "{\"phProv\": 0";
    }

    preCall << ", \"szContainer\": ";
    if (szContainer) {
        preCall << "\"0x" << std::hex << (PVOID)szContainer << "=0x";
        for (DWORD i = 0; szContainer[i] != '\0'; ++i) {
            preCall << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(szContainer[i]);
        }
        preCall << "\"";
    }
    else {
        preCall << "0";
    }

    preCall << ", \"szProvider\": ";
    if (szProvider) {
        preCall << "\"0x" << std::hex << (PVOID)szProvider << "=0x";
        for (DWORD i = 0; szProvider[i] != '\0'; ++i) {
            preCall << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(szProvider[i]);
        }
        preCall << "\"";
    }
    else {
        preCall << "0";
    }

    preCall << ", \"dwProvType\": " << std::hex << dwProvType;
    preCall << ", \"dwFlags\": " << std::hex << dwFlags << "}";
    logEntry.pre_call_parameters = preCall.str();

    // Actual API call
    BOOL result = CryptAcquireContextAActual(phProv, szContainer, szProvider, dwProvType, dwFlags);

    // Post-call parameter logging
    std::ostringstream postCall;
    if (phProv) {
        postCall << "{\"phProv\": \"0x";
        postCall << std::hex << phProv;
        postCall << "=";
        postCall << "0x" << std::hex << *reinterpret_cast<uint64_t*>(phProv);
        postCall << "\"";
    }
    else {
        postCall << "{\"phProv\": 0";
    }
    postCall << ", \"szContainer\": ";
    if (szContainer) {
        postCall << "\"0x" << std::hex << (PVOID)szContainer << "=0x";
        for (DWORD i = 0; szContainer[i] != '\0'; ++i) {
            postCall << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(szContainer[i]);
        }
        postCall << "\", ";
    }
    else {
        postCall << "0, ";
    }

    postCall << "\"szProvider\": ";
    if (szProvider) {
        postCall << "\"0x" << std::hex << (PVOID)szProvider << "=0x";
        for (DWORD i = 0; szProvider[i] != '\0'; ++i) {
            postCall << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(szProvider[i]);
        }
        postCall << "\", ";
    }
    else {
        postCall << "0, ";
    }

    postCall << "\"dwProvType\": " << std::hex << dwProvType << ", ";
    postCall << "\"dwFlags\": " << std::hex << dwFlags << "}";
    logEntry.post_call_parameters = postCall.str();

    // Result logging
    logEntry.result = std::to_string(result);

    // Log the entry
    std::ofstream logFile("api_logs.json", std::ios::app);
    if (logFile.is_open())
    {
        logFile << logEntry.toJSON() << "\n";
        logFile.close();
    }
    return result;
}
BOOL Hook_CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash)
{
    LogEntry logEntry;
    logEntry.apiName = "CryptCreateHash";

    // Pre-call parameter logging
    std::ostringstream preCall;
    preCall << "{\"hProv\": \"0x" << std::hex << hProv << "\", ";
    preCall << "\"Algid\": " << Algid << ", ";
    if (hKey)
    {
        preCall << "\"hKey\": \"0x" << std::hex << hKey << "\", ";
    }
    else
    {
        preCall << "\"hKey\": 0, ";
    }
    preCall << "\"dwFlags\": " << std::hex << dwFlags << ", ";
    if (phHash) {
        preCall << "\"phHash\": \"";
        preCall << "0x" << std::hex << phHash;
        preCall << "=";
        preCall << "0x" << std::hex << *reinterpret_cast<uint64_t*>(phHash);
        preCall << "\"";
    }
    else {
        preCall << "{\"phHash\": 0";
    }
    preCall << "}";
    logEntry.pre_call_parameters = preCall.str();

    // Actual API call
    BOOL result = CryptCreateHashActual(hProv, Algid, hKey, dwFlags, phHash);

    // Post-call parameter logging
    std::ostringstream postCall;
    postCall << "{\"hProv\": \"0x" << std::hex << hProv << "\", ";
    postCall << "\"Algid\": " << std::hex << Algid << ", ";
    if (hKey)
    {
        postCall << "\"hKey\": \"0x" << std::hex << hKey << "\", ";
    }
    else
    {
        postCall << "\"hKey\": 0, ";
    }
    postCall << "\"dwFlags\": " << std::hex << dwFlags << ", ";
    if (phHash) {
        postCall << "\"phHash\": \"";
        postCall << "0x" << std::hex << phHash;
        postCall << "=";
        postCall << "0x" << std::hex << *reinterpret_cast<uint64_t*>(phHash);
        postCall << "\"";
    }
    else {
        postCall << "{\"phHash\": 0";
    }
    postCall << "}";
    logEntry.post_call_parameters = postCall.str();

    // Result logging
    logEntry.result = std::to_string(result);

    // Log the entry
    //printf("%s\n", logEntry.toJSON().c_str());
    std::ofstream logFile("api_logs.json", std::ios::app);
    if (logFile.is_open())
    {
        logFile << logEntry.toJSON() << "\n";
        logFile.close();
    }
    return result;
}
BOOL Hook_CryptHashData(HCRYPTHASH hHash, const BYTE* pbData, DWORD dwDataLen, DWORD dwFlags)
{
    LogEntry logEntry;
    logEntry.apiName = "CryptHashData";

    // Pre-call parameter logging
    std::ostringstream preCall;
    preCall << "{\"hHash\": \"0x" << std::hex << hHash << "\", ";
    preCall << "\"pbData\": \"0x";
    preCall << std::hex << (PVOID)pbData << "=0x";
    for (DWORD i = 0; i < dwDataLen; i++) {
        preCall << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(pbData[i]);
    }
    preCall << "\", \"dwDataLen\": " << std::hex << dwDataLen << ", ";
    preCall << "\"dwFlags\": " << std::hex << dwFlags << "}";
    logEntry.pre_call_parameters = preCall.str();

    // Actual API call
    BOOL result = CryptHashDataActual(hHash, pbData, dwDataLen, dwFlags);

    // Post-call parameter logging
    logEntry.post_call_parameters = preCall.str();

    // Result logging
    logEntry.result = std::to_string(result);

    // Log the entry
    //printf("%s\n", logEntry.toJSON().c_str());
    std::ofstream logFile("api_logs.json", std::ios::app);
    if (logFile.is_open())
    {
        logFile << logEntry.toJSON() << "\n";
        logFile.close();
    }
    return result;

}
BOOL Hook_CryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY* phKey)
{
    LogEntry logEntry;
    logEntry.apiName = "CryptDeriveKey";

    // Pre-call parameter logging
    std::ostringstream preCall;
    if (hProv)
    {
        preCall << "{\"hProv\": \"0x" << std::hex << hProv << "\", ";
    }
    else
    {
        preCall << "{\"hProv\": 0, ";
    }
    preCall << "\"Algid\": " << std::hex << Algid << ", ";
    if (hBaseData)
    {
        preCall << "\"hBaseData\": \"0x" << std::hex << hBaseData << "\", ";
    }
    else
    {
        preCall << "\"hBaseData\": 0, ";
    }
    preCall << "\"dwFlags\": " << std::hex << dwFlags << ", ";
    if (phKey) {
        preCall << "\"phKey\": \"";
        preCall << "0x" << std::hex << phKey;
        preCall << "=";
        preCall << "0x" << std::hex << *reinterpret_cast<uint64_t*>(phKey);
        preCall << "\"";
    }
    else {
        preCall << "{\"phKey\": 0";
    }
    preCall << "}";
    logEntry.pre_call_parameters = preCall.str();

    // Actual API call
    BOOL result = CryptDeriveKeyActual(hProv, Algid, hBaseData, dwFlags, phKey);

    // Post-call parameter logging
    std::ostringstream postCall;
    if (hProv)
    {
        postCall << "{\"hProv\": \"0x" << std::hex << hProv << "\", ";
    }
    else
    {
        postCall << "{\"hProv\": 0, ";
    }
    postCall << "\"Algid\": " << std::hex << Algid << ", ";
    if (hBaseData)
    {
        postCall << "\"hBaseData\": \"0x" << std::hex << hBaseData << "\", ";
    }
    else
    {
        postCall << "\"hBaseData\": 0, ";
    }
    postCall << "\"dwFlags\": " << std::hex << dwFlags << ", ";
    if (phKey) {
        postCall << "\"phKey\": \"";
        postCall << "0x" << std::hex << phKey;
        postCall << "=";
        postCall << "0x" << std::hex << *reinterpret_cast<uint64_t*>(phKey);
        postCall << "\"";
    }
    else {
        postCall << "{\"phKey\": 0";
    }
    postCall << "}";
    logEntry.post_call_parameters = postCall.str();

    // Result logging
    logEntry.result = std::to_string(result);

    // Log the entry
    //printf("%s\n", logEntry.toJSON().c_str());
    std::ofstream logFile("api_logs.json", std::ios::app);
    if (logFile.is_open())
    {
        logFile << logEntry.toJSON() << "\n";
        logFile.close();
    }
    return result;
}
HANDLE Hook_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    LogEntry logEntry;
    logEntry.apiName = "CreateFileA";

    // Pre-call parameter logging
    std::ostringstream preCall;
    preCall << "{\"lpFileName\": ";
    if (lpFileName) {
        preCall << "\"0x" << std::hex << (PVOID)lpFileName << "=0x";
        for (DWORD i = 0; lpFileName[i] != '\0'; ++i) {
            preCall << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(lpFileName[i]);
        }
        preCall << "\"";
    }
    else {
        preCall << "0";
    }
    preCall << ", \"dwDesiredAccess\": " << std::hex << dwDesiredAccess;
    preCall << ", \"dwShareMode\": " << std::hex << dwShareMode;
    preCall << ", \"lpSecurityAttributes\": " << std::hex << lpSecurityAttributes;
    preCall << ", \"dwCreationDisposition\": " << std::hex << dwCreationDisposition;
    preCall << ", \"dwFlagsAndAttributes\": " << std::hex << dwFlagsAndAttributes;
    preCall << ", \"hTemplateFile\": " << std::hex << hTemplateFile;
    preCall << "}";
    logEntry.pre_call_parameters = preCall.str();
    logEntry.post_call_parameters = preCall.str();
    // Actual API call
    HANDLE result = CreateFileAActual(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    logEntry.result = std::to_string((uint64_t)result);

    // Log the entry
    //printf("%s\n", logEntry.toJSON().c_str());
    std::ofstream logFile("api_logs.json", std::ios::app);
    if (logFile.is_open())
    {
        logFile << logEntry.toJSON() << "\n";
        logFile.close();
    }
    return result;
}
BOOL Hook_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen)
{
    LogEntry logEntry;
    logEntry.apiName = "CryptEncrypt";

    // Pre-call parameter logging
    std::ostringstream preCall;
    if (hKey)
    {
        preCall << "{\"hKey\": \"0x" << std::hex << hKey << "\", ";
    }
    else
    {
        preCall << "\"hKey\": 0, ";
    }
    if (hHash)
    {
        preCall << "{\"hHash\": \"0x" << std::hex << hHash << "\", ";
    }
    else
    {
        preCall << "\"hHash\": 0, ";
    }
    preCall << "\"Final\": " << std::hex << Final << ", ";
    preCall << "\"dwFlags\": " << std::hex << dwFlags << ", ";
    preCall << "\"pbData\": \"0x" << std::hex << (PVOID)pbData << "=0x";
    for (DWORD i = 0; i < *pdwDataLen; i++) {
        preCall << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(pbData[i]);
    }
    preCall << "\", ";
    preCall << "\"pdwDataLen\": \"0x" << std::hex << pdwDataLen << "=" << std::hex << *pdwDataLen << "\", ";
    preCall << "\"dwBufLen\": " << std::hex << dwBufLen << "}";
    logEntry.pre_call_parameters = preCall.str();

    //Actual API Call
    BOOL result = CryptEncryptActual(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);

    //Post-call parameter logging
    std::ostringstream postCall;
    if (hKey)
    {
        postCall << "{\"hKey\": \"0x" << std::hex << hKey << "\", ";
    }
    else
    {
        postCall << "\"hKey\": 0, ";
    }
    if (hHash)
    {
        postCall << "{\"hHash\": \"0x" << std::hex << hHash << "\", ";
    }
    else
    {
        postCall << "\"hHash\": 0, ";
    }
    postCall << "\"Final\": " << std::hex << Final << ", ";
    postCall << "\"dwFlags\": " << std::hex << dwFlags << ", ";
    postCall << "\"pbData\": \"0x" << std::hex << (PVOID)pbData << "=0x";
    for (DWORD i = 0; i < *pdwDataLen; i++) {
        postCall << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(pbData[i]);
    }
    postCall << "\", ";
    postCall << "\"pdwDataLen\": \"0x" << std::hex << pdwDataLen << "=" << std::hex << *pdwDataLen << "\", ";
    postCall << "\"dwBufLen\": " << std::hex << dwBufLen << "}";
    logEntry.post_call_parameters = postCall.str();

    // Result logging
    logEntry.result = std::to_string(result);

    // Log the entry
    //printf("%s\n", logEntry.toJSON().c_str());
    std::ofstream logFile("api_logs.json", std::ios::app);
    if (logFile.is_open())
    {
        logFile << logEntry.toJSON() << "\n";
        logFile.close();
    }
    return result;
}
BOOL Hook_CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen)
{
    LogEntry logEntry;
    logEntry.apiName = "CryptDecrypt";

    // Pre-call parameter logging
    std::ostringstream preCall;
    if (hKey)
    {
        preCall << "{\"hKey\": \"0x" << std::hex << hKey << "\", ";
    }
    else
    {
        preCall << "\"hKey\": 0, ";
    }
    if (hHash)
    {
        preCall << "{\"hHash\": \"0x" << std::hex << hHash << "\", ";
    }
    else
    {
        preCall << "\"hHash\": 0, ";
    }
    preCall << "\"Final\": " << std::hex << Final << ", ";
    preCall << "\"dwFlags\": " << std::hex << dwFlags << ", ";
    preCall << "\"pbData\": \"0x" << std::hex << (PVOID)pbData << "=0x";
    for (DWORD i = 0; i < *pdwDataLen; i++) {
        preCall << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(pbData[i]);
    }
    preCall << "\", ";
    preCall << "\"pdwDataLen\": \"0x" << std::hex << pdwDataLen << "=" << std::hex << *pdwDataLen << "\", ";
    preCall << "}";
    logEntry.pre_call_parameters = preCall.str();

    //Actual API Call
    BOOL result = CryptDecryptActual(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);

    //Post-call parameter logging
    std::ostringstream postCall;
    if (hKey)
    {
        postCall << "{\"hKey\": \"0x" << std::hex << hKey << "\", ";
    }
    else
    {
        postCall << "\"hKey\": 0, ";
    }
    if (hHash)
    {
        postCall << "{\"hHash\": \"0x" << std::hex << hHash << "\", ";
    }
    else
    {
        postCall << "\"hHash\": 0, ";
    }
    postCall << "\"Final\": " << std::hex << Final << ", ";
    postCall << "\"dwFlags\": " << std::hex << dwFlags << ", ";
    postCall << "\"pbData\": \"0x" << std::hex << (PVOID)pbData << "=0x";
    for (DWORD i = 0; i < *pdwDataLen; i++) {
        postCall << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(pbData[i]);
    }
    postCall << "\", ";
    postCall << "\"pdwDataLen\": \"0x" << std::hex << pdwDataLen << "=" << std::hex << *pdwDataLen << "\", ";
    postCall << "}";
    logEntry.post_call_parameters = postCall.str();

    // Result logging
    logEntry.result = std::to_string(result);

    // Log the entry
    //printf("%s\n", logEntry.toJSON().c_str());
    std::ofstream logFile("api_logs.json", std::ios::app);
    if (logFile.is_open())
    {
        logFile << logEntry.toJSON() << "\n";
        logFile.close();
    }
    return result;
}

std::vector<PVOID*> originals = { (PVOID*)&CryptAcquireContextAActual ,(PVOID*)&CryptCreateHashActual, (PVOID*)&CryptHashDataActual, (PVOID*)&CryptDeriveKeyActual, (PVOID*)&CreateFileAActual, (PVOID*)&CryptEncryptActual, (PVOID*)&CryptDecryptActual };
std::vector<PVOID> hooks = { Hook_CryptAcquireContextA, Hook_CryptCreateHash, Hook_CryptHashData, Hook_CryptDeriveKey, Hook_CreateFileA, Hook_CryptEncrypt, Hook_CryptDecrypt };

BOOL InstallHooks()
{
    DWORD error = NO_ERROR;

    error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        //printf("Failed to begin Detour transaction; error: %d\n", error);
        return FALSE;
    }
    error = DetourUpdateThread(GetCurrentThread());
    if (error != NO_ERROR) {
        //printf("Failed to update thread for Detour transaction; error: %d\n", error);
        return FALSE;
    }

    for (DWORD i = 0; i < originals.size(); i++)
    {
        error = DetourAttach(originals[i], hooks[i]);
        if (error != NO_ERROR) {
            //printf("Failed to attach Detour hook function; error: %d\n", error);
            return FALSE;
        }
    }

    error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        //printf("Failed to commit Detour transaction; error: %d\n", error);
        return FALSE;
    }
    return TRUE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InstallHooks();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

