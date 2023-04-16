#include <iostream>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <windows.h>
#include <Wincrypt.h>
#pragma comment(lib, "Advapi32.lib")

class DES {
private:
    BYTE skey[1000];
    char skeyString[1000];
    static BYTE *raw;
    std::string inputMessage, encryptedData, decryptedMessage;

    void generateSymmetricKey() {
        srand(time(NULL));
        int num = rand() % 10000;
        char knum[10];
        itoa(num, knum, 10);
        BYTE* knumb = reinterpret_cast<BYTE*>(knum);
        raw = getRawKey(knumb);
        strcpy_s(skeyString, reinterpret_cast<char*>(raw));
        std::cout << "DES Symmetric key = " << skeyString << std::endl;
    }

    static BYTE* getRawKey(BYTE* seed) {
        HCRYPTPROV hProv;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        {
            std::cout << "Error: could not acquire crypt context" << std::endl;
            exit(1);
        }
        HCRYPTKEY hKey;
        if (!CryptGenKey(hProv, CALG_DES, CRYPT_EXPORTABLE, &hKey))
        {
            std::cout << "Error: could not generate DES key" << std::endl;
            exit(1);
        }
        DWORD dwBlobLen;
        if (!CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &dwBlobLen))
        {
            std::cout << "Error: could not export key" << std::endl;
            exit(1);
        }
        BYTE* pbKeyBlob = new BYTE[dwBlobLen];
        if (!CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, pbKeyBlob, &dwBlobLen))
        {
            std::cout << "Error: could not export key" << std::endl;
            exit(1);
        }
        if (!CryptDestroyKey(hKey))
        {
            std::cout << "Error: could not destroy key" << std::endl;
            exit(1);
        }
        if (!CryptReleaseContext(hProv, 0))
        {
            std::cout << "Error: could not release context" << std::endl;
            exit(1);
        }
        raw = pbKeyBlob;
        return raw;
    }

    static BYTE* encrypt(BYTE* raw, BYTE* clear) {
        HCRYPTPROV hProv;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        {
            std::cout << "Error: could not acquire crypt context" << std::endl;
            exit(1);
        }
        HCRYPTKEY hKey;
        if (!CryptImportKey(hProv, raw, 8, NULL, 0, &hKey))
        {
            std::cout << "Error: could not import key" << std::endl;
            exit(1);
        }
        DWORD dwDataLen = strlen(reinterpret_cast<char*>(clear)) + 1;
        DWORD dwBufLen = dwDataLen;
        if (!CryptEncrypt(hKey, NULL, TRUE, 0, NULL, &dwBufLen, dwDataLen))
        {
            std::cout << "Error: could not determine buffer length" << std::endl;
            exit(1);
        }
        BYTE
