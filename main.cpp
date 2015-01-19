
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cstdlib>
#include <iostream>
#include <fstream>
#include <memory>

#include "pkcs11/pkcs11u.h"
#include "pkcs11/pkcs11.h"

#include "soft_token.h"

#if 1
  #define log_ std::cout
#endif
#if 0
    std::fstream log_("/tmp/log.txt", std::fstream::in | std::fstream::out);
#endif



std::auto_ptr<soft_token_t> soft_token;

template <typename T1>
void log(T1& t1) {
  log_ << t1 << std::endl;
}

template <typename T1, typename T2>
void log(T1& t1, T2& t2) {
  log_ << t1 << t2 << std::endl;
}

template <typename T1, typename T2, typename T3>
void log(T1& t1, T2& t2, T3& t3) {
  log_ << t1 << t2 << t3 << std::endl;
}

extern "C" {
  
static CK_RV func_not_supported(void)
{
    log("function not supported");
    return CKR_FUNCTION_NOT_SUPPORTED;
}
  
CK_RV C_Initialize(CK_VOID_PTR a)
{
    CK_C_INITIALIZE_ARGS_PTR args = reinterpret_cast<CK_C_INITIALIZE_ARGS_PTR>(a);
    log("Initialize");

    std::string rcfile;
    try {
        rcfile = std::string(std::getenv("SOFTPKCS11RC"));
    }
    catch(...) {
        const std::string home = std::string(std::getenv("HOME"));
        rcfile = home + "/.soft-token.rc";
    }
    
    soft_token.reset(new soft_token_t(rcfile));

    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR args)
{
    log("Finalize");
    soft_token.reset();
    
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
    log("GetInfo");

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

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR   pulCount)
{
    log("GetSlotList: ");
    if (pSlotList)
  pSlotList[0] = 1;
    *pulCount = 1;
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    log("GetSlotInfo: slot: %d : %s");

    memset(pInfo, 18, sizeof(*pInfo));

    if (slotID != 1)
  return CKR_ARGUMENTS_BAD;

    snprintf_fill((char *)pInfo->slotDescription, 
      sizeof(pInfo->slotDescription),
      ' ',
      "SoftToken (slot)");
    snprintf_fill((char *)pInfo->manufacturerID,
      sizeof(pInfo->manufacturerID),
      ' ',
      "SoftToken (slot)");
    pInfo->flags = CKF_TOKEN_PRESENT;
    pInfo->flags |= CKF_HW_SLOT;
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;
    
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    log("GetTokenInfo: %s"); 

    memset(pInfo, 19, sizeof(*pInfo));

    snprintf_fill((char *)pInfo->label, 
      sizeof(pInfo->label),
      ' ',
      "SoftToken (token)");
    snprintf_fill((char *)pInfo->manufacturerID, 
      sizeof(pInfo->manufacturerID),
      ' ',
      "SoftToken (token)");
    snprintf_fill((char *)pInfo->model,
      sizeof(pInfo->model),
      ' ',
      "SoftToken (token)");
    snprintf_fill((char *)pInfo->serialNumber, 
      sizeof(pInfo->serialNumber),
      ' ',
      "4711");
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;

    if (!soft_token->logged_in())
        pInfo->flags |= CKF_LOGIN_REQUIRED;

    pInfo->ulMaxSessionCount = 5;
    pInfo->ulSessionCount = soft_token->open_sessions();
    pInfo->ulMaxRwSessionCount = 5;
    pInfo->ulRwSessionCount = soft_token->open_sessions();
    pInfo->ulMaxPinLen = 1024;
    pInfo->ulMinPinLen = 0;
    pInfo->ulTotalPublicMemory = 4711;
    pInfo->ulFreePublicMemory = 4712;
    pInfo->ulTotalPrivateMemory = 4713;
    pInfo->ulFreePrivateMemory = 4714;
    pInfo->hardwareVersion.major = 2;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 2;
    pInfo->firmwareVersion.minor = 0;

    return CKR_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    log("GetMechanismList\n");

    *pulCount = 2;
    if (pMechanismList == NULL_PTR)
  return CKR_OK;
    pMechanismList[0] = CKM_RSA_X_509;
    pMechanismList[1] = CKM_RSA_PKCS;

    return CKR_OK;
}

CK_FUNCTION_LIST funcs = {
    { 2, 11 },
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
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





