
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

#include <boost/foreach.hpp>

#include "pkcs11/pkcs11u.h"
#include "pkcs11/pkcs11.h"

#include "soft_token.h"


std::auto_ptr<soft_token_t> soft_token;

static void log(const std::string& str) {
    std::cout << str << std::endl;
}

static void st_logf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vdprintf(STDOUT_FILENO, fmt, ap);
    va_end(ap);
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
    log("** GetInfo");
    
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
    st_logf("C_GetSlotList\n");

    if (pSlotList) {
        pSlotList[0] = 1;
    }
    
    *pulCount = 1;

    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    st_logf("GetSlotInfo: slot: %d\n", (int) slotID);

    memset(pInfo, 18, sizeof(*pInfo));

     if (slotID != 1) return CKR_ARGUMENTS_BAD;


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
    if (pMechanismList == NULL_PTR) return CKR_OK;

    pMechanismList[0] = CKM_RSA_X_509;
    pMechanismList[1] = CKM_RSA_PKCS;

    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    st_logf("GetMechanismInfo: slot %d type: %d\n", (int)slotID, (int)type);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken(CK_SLOT_ID slotID,
        CK_UTF8CHAR_PTR pPin,
        CK_ULONG ulPinLen,
        CK_UTF8CHAR_PTR pLabel)
{
    st_logf("InitToken: slot %d\n", (int)slotID);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID,
          CK_FLAGS flags,
          CK_VOID_PTR pApplication,
          CK_NOTIFY Notify,
          CK_SESSION_HANDLE_PTR phSession)
{
    int i;

    st_logf("OpenSession: slot: %d\n", (int)slotID);

//     if (soft_token.open_sessions == MAX_NUM_SESSION) return CKR_SESSION_COUNT;

//     soft_token.application = pApplication;
//     soft_token.notify = Notify;

//     for (i = 0; i < MAX_NUM_SESSION; i++)
//         if (soft_token.state[i].session_handle == CK_INVALID_HANDLE) break;
//         
//     if (i == MAX_NUM_SESSION)
//     abort();

//     soft_token.open_sessions++;

//     soft_token.state[i].session_handle =
//     (CK_SESSION_HANDLE)(random() & 0xfffff);
    *phSession = 44;

    return CKR_OK;
}

static void
print_attributes(const CK_ATTRIBUTE *attributes,
         CK_ULONG num_attributes)
{
    CK_ULONG i;

    st_logf("find objects: attrs: %lu\n", (unsigned long)num_attributes);

    for (i = 0; i < num_attributes; i++) {
    st_logf("  type: ");
    switch (attributes[i].type) {
    case CKA_TOKEN: {
        CK_BBOOL *ck_true;
        if (attributes[i].ulValueLen != sizeof(CK_BBOOL)) {
//         application_error("token attribute wrong length\n");
        break;
        }
        ck_true = attributes[i].pValue;
        st_logf("token: %s", *ck_true ? "TRUE" : "FALSE");
        break;
    }
    case CKA_CLASS: {
        CK_OBJECT_CLASS *klass;
        if (attributes[i].ulValueLen != sizeof(CK_ULONG)) {
//         application_error("class attribute wrong length\n");
        break;
        }
        klass = attributes[i].pValue;
        st_logf("class ");
        switch (*klass) {
        case CKO_CERTIFICATE:
        st_logf("certificate");
        break;
        case CKO_PUBLIC_KEY:
        st_logf("public key");
        break;
        case CKO_PRIVATE_KEY:
        st_logf("private key");
        break;
        case CKO_SECRET_KEY:
        st_logf("secret key");
        break;
        case CKO_DOMAIN_PARAMETERS:
        st_logf("domain parameters");
        break;
        default:
        st_logf("[class %lx]", (long unsigned)*klass);
        break;
        }
        break;
    }
    case CKA_PRIVATE:
        st_logf("private");
        break;
    case CKA_LABEL:
        st_logf("label");
        break;
    case CKA_APPLICATION:
        st_logf("application");
        break;
    case CKA_VALUE:
        st_logf("value");
        break;
    case CKA_ID:
        st_logf("id");
        break;
    default:
        st_logf("[unknown 0x%08lx]", (unsigned long)attributes[i].type);
        break;
    }
    st_logf("\n");
    }
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
//     struct session_state *state;

    st_logf("FindObjectsInit: %d\n", hSession);

//     VERIFY_SESSION_HANDLE(hSession, &state);

//     if (state->find.next_object != -1) {
//         application_error("application didn't do C_FindObjectsFinal\n");
//         find_object_final(state);
//     }
    if (ulCount) {
        CK_ULONG i;
        size_t len;

        print_attributes(pTemplate, ulCount);

//         state->find.attributes = 
//             calloc(1, ulCount * sizeof(state->find.attributes[0]));
//         if (state->find.attributes == NULL)
//             return CKR_DEVICE_MEMORY;
//         for (i = 0; i < ulCount; i++) {
//             state->find.attributes[i].pValue = 
//             malloc(pTemplate[i].ulValueLen);
//             if (state->find.attributes[i].pValue == NULL) {
//             find_object_final(state);
//             return CKR_DEVICE_MEMORY;
//             }
//             memcpy(state->find.attributes[i].pValue,
//             pTemplate[i].pValue, pTemplate[i].ulValueLen);
//             state->find.attributes[i].type = pTemplate[i].type;
//             state->find.attributes[i].ulValueLen = pTemplate[i].ulValueLen;
//         }
//         state->find.num_attributes = ulCount;
//         state->find.next_object = 0;
    } else {
        st_logf("find all objects\n");
//         state->find.attributes = NULL;
//         state->find.num_attributes = 0;
//         state->find.next_object = 0;
    }

    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
          CK_OBJECT_HANDLE_PTR phObject,
          CK_ULONG ulMaxObjectCount,
          CK_ULONG_PTR pulObjectCount)
{
    struct session_state *state;
    int i;

    st_logf("FindObjects %d\n", hSession);

//     VERIFY_SESSION_HANDLE(hSession, &state);

//     if (state->find.next_object == -1) {
//     application_error("application didn't do C_FindObjectsInit\n");
//         return CKR_ARGUMENTS_BAD;
//     }
    
    if (ulMaxObjectCount == 0) {
//     application_error("application asked for 0 objects\n");
        return CKR_ARGUMENTS_BAD;
    }
    *pulObjectCount = 0;
    BOOST_FOREACH(auto id, soft_token->object_ids()) {
        *phObject++ = id;
        (*pulObjectCount)++;
        ulMaxObjectCount--;
        if (ulMaxObjectCount == 0) break;
    }
    
    return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    struct session_state *state;
    struct st_object *obj;
    CK_ULONG i;
    CK_RV ret;
    int j;

    st_logf("GetAttributeValue: %lx ulCount: %d\n", hObject, ulCount);
//     VERIFY_SESSION_HANDLE(hSession, &state);

//     if ((ret = object_handle_to_object(hObject, &obj)) != CKR_OK) {
//     st_logf("object not found: %lx\n",
//         (unsigned long)HANDLE_OBJECT_ID(hObject));
//     return ret;
//     }

    auto attrs = soft_token->attributes(hObject);
    
    for (i = 0; i < ulCount; i++) {
        st_logf("   getting 0x%08lx\n", (unsigned long)pTemplate[i].type);
        

//         memcpy(pTemplate[i].pValue, attrs[pTemplate[i].type].pValue, attrs[pTemplate[i].type].ulValueLen);
        
        
//         for (j = 0; j < obj->num_attributes; j++) {
//             if (obj->attrs[j].secret) {
//             pTemplate[i].ulValueLen = (CK_ULONG)-1;
//             break;
//             }
//             if (pTemplate[i].type == obj->attrs[j].attribute.type) {
//             if (pTemplate[i].pValue != NULL_PTR && obj->attrs[j].secret == 0) {
//                 if (pTemplate[i].ulValueLen >= obj->attrs[j].attribute.ulValueLen)
//                 memcpy(pTemplate[i].pValue, obj->attrs[j].attribute.pValue,
//                     obj->attrs[j].attribute.ulValueLen);
//             }
//             pTemplate[i].ulValueLen = obj->attrs[j].attribute.ulValueLen;
//             break;
//             }
//         }
//         if (j == obj->num_attributes) {
//             st_logf("key type: 0x%08lx not found\n", (unsigned long)pTemplate[i].type);
//             pTemplate[i].ulValueLen = (CK_ULONG)-1;
//         }

    }
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
    C_GetMechanismInfo,
    C_InitToken,
    (void *)func_not_supported, /* C_InitPIN */
    (void *)func_not_supported, /* C_SetPIN */
    C_OpenSession,
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
    C_GetAttributeValue,
    (void *)func_not_supported, /* C_SetAttributeValue */
    C_FindObjectsInit,
    C_FindObjects,
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





