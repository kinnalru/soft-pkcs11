
#include <fstream>

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pkcs11/pkcs11u.h"
#include "pkcs11/pkcs11.h"

std::fstream log("/tmp/log.txt", std::fstream::in | std::fstream::out);

extern "C" {
  
static CK_RV func_not_supported(void)
{
    log << "function not supported" << std::endl;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
  
CK_RV C_Initialize(CK_VOID_PTR a)
{
    CK_C_INITIALIZE_ARGS_PTR args = reinterpret_cast<CK_C_INITIALIZE_ARGS_PTR>(a);
    log <<  "Initialize" << std::endl;

    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR args)
{
    log <<  "Finalize" << std::endl;

    return CKR_OK;
}

static void snprintf_fill(char *str, size_t size, char fillchar, const char *fmt, ...)
{
    int len;
    va_list ap;
    len = vsnprintf(str, size, fmt, ap);
    va_end(ap);
    if (len < 0 || len > size)
  return;
    while(len < size)
  str[len++] = fillchar;
}

CK_RV C_GetInfo(CK_INFO_PTR args)
{
    log <<  "GetInfo" << std::endl;

    memset(args, 17, sizeof(*args));
    args->cryptokiVersion.major = 2;
    args->cryptokiVersion.minor = 10;
    snprintf_fill((char *)args->manufacturerID, 
      sizeof(args->manufacturerID),
      ' ',
      "SoftToken");
    snprintf_fill((char *)args->libraryDescription, 
      sizeof(args->libraryDescription), ' ',
      "SoftToken");
    args->libraryVersion.major = 1;
    args->libraryVersion.minor = 8;

    return CKR_OK;
}

extern CK_FUNCTION_LIST funcs;

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    *ppFunctionList = &funcs;
    return CKR_OK;
}

CK_FUNCTION_LIST funcs = {
    { 2, 11 },
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
        (void *)func_not_supported, //C_GetSlotList,
        (void *)func_not_supported, //C_GetSlotInfo,
        (void *)func_not_supported, //C_GetTokenInfo,
        (void *)func_not_supported, //C_GetMechanismList,
        (void *)func_not_supported, //C_GetMechanismInfo,
        (void *)func_not_supported, //C_InitToken,
    (void *)func_not_supported, /* C_InitPIN */
    (void *)func_not_supported, /* C_SetPIN */
        (void *)func_not_supported, //C_OpenSession,
        (void *)func_not_supported, //C_CloseSession,
        (void *)func_not_supported, //C_CloseAllSessions,
        (void *)func_not_supported, //C_GetSessionInfo,
    (void *)func_not_supported, /* C_GetOperationState */
    (void *)func_not_supported, /* C_SetOperationState */
        (void *)func_not_supported, //C_Login,
        (void *)func_not_supported, //C_Logout,
    (void *)func_not_supported, /* C_CreateObject */
    (void *)func_not_supported, /* C_CopyObject */
    (void *)func_not_supported, /* C_DestroyObject */
    (void *)func_not_supported, /* C_GetObjectSize */
        (void *)func_not_supported, //C_GetAttributeValue,
    (void *)func_not_supported, /* C_SetAttributeValue */
        (void *)func_not_supported, //C_FindObjectsInit,
        (void *)func_not_supported, //C_FindObjects,
        (void *)func_not_supported, //C_FindObjectsFinal,
        (void *)func_not_supported, //C_EncryptInit,
        (void *)func_not_supported, //C_Encrypt,
        (void *)func_not_supported, //C_EncryptUpdate,
        (void *)func_not_supported, //C_EncryptFinal,
        (void *)func_not_supported, //C_DecryptInit,
        (void *)func_not_supported, //C_Decrypt,
        (void *)func_not_supported, //C_DecryptUpdate,
        (void *)func_not_supported, //C_DecryptFinal,
        (void *)func_not_supported, //C_DigestInit,
    (void *)func_not_supported, /* C_Digest */
    (void *)func_not_supported, /* C_DigestUpdate */
    (void *)func_not_supported, /* C_DigestKey */
    (void *)func_not_supported, /* C_DigestFinal */
        (void *)func_not_supported, //C_SignInit,
        (void *)func_not_supported, //C_Sign,
        (void *)func_not_supported, //C_SignUpdate,
        (void *)func_not_supported, //C_SignFinal,
    (void *)func_not_supported, /* C_SignRecoverInit */
    (void *)func_not_supported, /* C_SignRecover */
        (void *)func_not_supported, //C_VerifyInit,
        (void *)func_not_supported, //C_Verify,
        (void *)func_not_supported, //C_VerifyUpdate,
        (void *)func_not_supported, //C_VerifyFinal,
    (void *)func_not_supported, /* C_VerifyRecoverInit */
    (void *)func_not_supported, /* C_VerifyRecover */
    (void *)func_not_supported, /* C_DigestEncryptUpdate */
    (void *)func_not_supported, /* C_DecryptDigestUpdate */
    (void *)func_not_supported, /* C_SignEncryptUpdate */
    (void *)func_not_supported, /* C_DecryptVerifyUpdate */
    (void *)func_not_supported, /* C_GenerateKey */
    (void *)func_not_supported, /* C_GenerateKeyPair */
    (void *)func_not_supported, /* C_WrapKey */
    (void *)func_not_supported, /* C_UnwrapKey */
    (void *)func_not_supported, /* C_DeriveKey */
    (void *)func_not_supported, /* C_SeedRandom */
        (void *)func_not_supported, //C_GenerateRandom,
    (void *)func_not_supported, /* C_GetFunctionStatus */
    (void *)func_not_supported, /* C_CancelFunction */
    (void *)func_not_supported  /* C_WaitForSlotEvent */
};










}





