#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "kernel32.lib")
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 // Windows Vista or later
#endif
void EncryptDecryptFile(const char* filename) {
    BOOL result;
    HANDLE hFile;
    hFile = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file: %s\n", filename);
        return;
    }

    // Step 1: Initialize cryptographic context
    HCRYPTPROV hProv;
    result = CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, 0);
    if (!result) {
        printf("CryptAcquireContextA failed. Error code: %u\n", GetLastError());
        CloseHandle(hFile);
        return;
    }

    // Step 2: Create a hash object
    HCRYPTHASH hHash;
    result = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
    if (!result) {
        printf("CryptCreateHash failed. Error code: %u\n", GetLastError());
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return;
    }

    // Step 3: Hash the file data
    const char* data = "Dummy data for hashing.";
    result = CryptHashData(hHash, (BYTE*)data, strlen(data), 0);
    if (!result) {
        printf("CryptHashData failed. Error code: %u\n", GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return;
    }

    // Step 4: Derive a key from the hash
    HCRYPTKEY hKey;
    result = CryptDeriveKey(hProv, CALG_RC2, hHash, CRYPT_EXPORTABLE, &hKey);
    if (!result) {
        printf("CryptDeriveKey failed. Error code: %u\n", GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return;
    }

    // Step 5: Read file content and adjust buffer size
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    DWORD bufferSize = dwFileSize;
    BYTE* buffer = (BYTE*)malloc(dwFileSize);
    DWORD bytesRead;
    result = ReadFile(hFile, buffer, dwFileSize, &bytesRead, NULL);
    if (!result || bytesRead != dwFileSize) {
        printf("Failed to read the file.\n");
        free(buffer);
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return;
    }

    // Ensure the buffer can hold the encrypted data
    bufferSize += 16; // Add extra space for padding
    buffer = (BYTE*)realloc(buffer, bufferSize);

    // Encrypt the data
    DWORD encryptedSize = bytesRead;
    result = CryptEncrypt(hKey, 0, TRUE, 0, buffer, &encryptedSize, bufferSize);
    if (!result) {
        printf("CryptEncrypt failed. Error code: %u\n", GetLastError());
        free(buffer);
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return;
    }

    // Write encrypted data back to the file
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    DWORD bytesWritten;
    result = WriteFile(hFile, buffer, encryptedSize, &bytesWritten, NULL);
    if (!result || bytesWritten != encryptedSize) {
        printf("Failed to write encrypted data back to file.\n");
    }

    // Step 6: Decrypt the data
    result = CryptDecrypt(hKey, 0, TRUE, 0, buffer, &encryptedSize);
    if (!result) {
        printf("CryptDecrypt failed. Error code: %u\n", GetLastError());
        free(buffer);
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return;
    }

    // printf("Decrypted data: %s\n", buffer);

    // Clean up
    free(buffer);
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
}

int main() {
    const char* filename = ".\\testFile.txt";
    LoadLibraryA(".\\Monitor.dll");
    // Encrypt and Decrypt the file
    EncryptDecryptFile(filename);

    return 0;
}
