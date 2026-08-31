#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"crypt32.lib")

__declspec(dllexport)
char* ConvertCspPrivateBlobToPem(const unsigned char* priv_blob, ULONG blob_len)
{
    BCRYPT_ALG_HANDLE hRsa;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hRsa, BCRYPT_RSA_ALGORITHM, NULL,0);
    if(!BCRYPT_SUCCESS(st)) return NULL;

    BCRYPT_KEY_HANDLE hPriv;
    st = BCryptImportKeyPair(hRsa, NULL, BCRYPT_RSAPRIVATE_BLOB, &hPriv, priv_blob, blob_len,0);
    if(!BCRYPT_SUCCESS(st)) {
        BCryptCloseAlgorithmProvider(hRsa,0);
        return NULL;
    }

    ULONG der_len = 0;
    st = BCryptExportKey(hPriv, NULL, BCRYPT_PRIVATE_KEY_BLOB, NULL,0, &der_len,0);
    unsigned char* der_buf = (unsigned char*)LocalAlloc(LPTR, der_len);
    st = BCryptExportKey(hPriv, NULL, BCRYPT_PRIVATE_KEY_BLOB, der_buf, der_len, &der_len,0);

    DWORD b64_len = 0;
    CryptBinaryToStringA(der_buf, der_len, CRYPT_STRING_BASE64, NULL, &b64_len);
    char* b64_buf = (char*)LocalAlloc(LPTR, b64_len + 256);
    CryptBinaryToStringA(der_buf, der_len, CRYPT_STRING_BASE64, b64_buf, &b64_len);

    char* pem_out = (char*)LocalAlloc(LPTR, b64_len + 128);
    sprintf_s(pem_out, b64_len+128,
        "-----BEGIN PRIVATE KEY-----\n%s-----END PRIVATE KEY-----\n",
        b64_buf);

    LocalFree(der_buf);
    LocalFree(b64_buf);
    BCryptDestroyKey(hPriv);
    BCryptCloseAlgorithmProvider(hRsa,0);
    return pem_out;
}

__declspec(dllexport)
void FreeMemory(void* p)
{
    if(p) LocalFree(p);
}
