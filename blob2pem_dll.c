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
    if (priv_blob == NULL || blob_len == 0)
        return NULL;

    BCRYPT_ALG_HANDLE hRsa = NULL;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hRsa, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st))
        return NULL;

    BCRYPT_KEY_HANDLE hPriv = NULL;
    st = BCryptImportKeyPair(hRsa, NULL, BCRYPT_RSAPRIVATE_BLOB, &hPriv, priv_blob, blob_len, 0);
    if (!BCRYPT_SUCCESS(st))
    {
        BCryptCloseAlgorithmProvider(hRsa, 0);
        return NULL;
    }

    ULONG der_len = 0;
    st = BCryptExportKey(hPriv, NULL, BCRYPT_PRIVATE_KEY_BLOB, NULL, 0, &der_len, 0);
    if (!BCRYPT_SUCCESS(st) || der_len == 0)
    {
        BCryptDestroyKey(hPriv);
        BCryptCloseAlgorithmProvider(hRsa, 0);
        return NULL;
    }

    unsigned char* der_buf = (unsigned char*)LocalAlloc(LPTR, der_len);
    if (der_buf == NULL)
    {
        BCryptDestroyKey(hPriv);
        BCryptCloseAlgorithmProvider(hRsa, 0);
        return NULL;
    }

    st = BCryptExportKey(hPriv, NULL, BCRYPT_PRIVATE_KEY_BLOB, der_buf, der_len, &der_len, 0);
    if (!BCRYPT_SUCCESS(st))
    {
        LocalFree(der_buf);
        BCryptDestroyKey(hPriv);
        BCryptCloseAlgorithmProvider(hRsa, 0);
        return NULL;
    }

    DWORD b64_len = 0;
    if (!CryptBinaryToStringA(der_buf, der_len, CRYPT_STRING_BASE64, NULL, &b64_len))
    {
        LocalFree(der_buf);
        BCryptDestroyKey(hPriv);
        BCryptCloseAlgorithmProvider(hRsa, 0);
        return NULL;
    }

    char* b64_buf = (char*)LocalAlloc(LPTR, b64_len);
    if (b64_buf == NULL)
    {
        LocalFree(der_buf);
        BCryptDestroyKey(hPriv);
        BCryptCloseAlgorithmProvider(hRsa, 0);
        return NULL;
    }

    if (!CryptBinaryToStringA(der_buf, der_len, CRYPT_STRING_BASE64, b64_buf, &b64_len))
    {
        LocalFree(b64_buf);
        LocalFree(der_buf);
        BCryptDestroyKey(hPriv);
        BCryptCloseAlgorithmProvider(hRsa, 0);
        return NULL;
    }

    const char head[] = "-----BEGIN RSA PRIVATE KEY-----\n";
    const char tail[] = "-----END RSA PRIVATE KEY-----\n";
    size_t pem_total = sizeof(head)-1 + b64_len + sizeof(tail)-1 + 1;

    char* pem_out = (char*)LocalAlloc(LPTR, pem_total);
    if (pem_out == NULL)
    {
        LocalFree(b64_buf);
        LocalFree(der_buf);
        BCryptDestroyKey(hPriv);
        BCryptCloseAlgorithmProvider(hRsa, 0);
        return NULL;
    }

    // 修复：移除snprintf_s，解决LNK2019链接未定义
    sprintf(pem_out, "%s%s%s", head, b64_buf, tail);

    LocalFree(der_buf);
    LocalFree(b64_buf);
    BCryptDestroyKey(hPriv);
    BCryptCloseAlgorithmProvider(hRsa, 0);

    return pem_out;
}

__declspec(dllexport)
void FreeMemory(void* p)
{
    if (p)
        LocalFree(p);
}
