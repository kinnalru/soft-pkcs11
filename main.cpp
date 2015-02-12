
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
#include <algorithm>
#include <memory>
#include <list>
#include <set>

#include <boost/foreach.hpp>

#include "pkcs11/pkcs11u.h"
#include "pkcs11/pkcs11.h"

#include "tools.h"
#include "soft_token.h"


std::auto_ptr<soft_token_t> soft_token;

static void log(const std::string& str) {
    st_logf("%s\n", str.c_str());
}



template <int ID>
struct func_t {
    static CK_RV not_supported() {
        st_logf("function %d not supported\n", ID);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
};


struct session_t {
    
    static std::list<session_t>::iterator create() {
        return _sessions.insert(_sessions.end(), session_t(++_id));
    };
    
    static void destroy(CK_SESSION_HANDLE id) {
        auto it = find(id);
        if (it != _sessions.end()) {
            _sessions.erase(it);
        }
    }
    
    static std::list<session_t>::iterator find(CK_SESSION_HANDLE id) {
        return std::find(_sessions.begin(), _sessions.end(), id);
    };
    
    static std::list<session_t>::iterator end() {
        return _sessions.end();
    }
    
    static std::list<session_t>::size_type count() {return _sessions.size();}

    operator CK_SESSION_HANDLE() const {return id;}
    
    
    const CK_SESSION_HANDLE id;
    handle_iterator_t objects_iterator;
    CK_OBJECT_HANDLE sign_key;
    CK_MECHANISM sign_mechanism;
    
private:
    session_t(CK_SESSION_HANDLE id) : id(id) {}

private:
    static CK_SESSION_HANDLE _id;
    static std::list<session_t> _sessions;
};


CK_SESSION_HANDLE session_t::_id = 0;
std::list<session_t> session_t::_sessions = std::list<session_t>();



extern "C" {
  
  
CK_RV C_Initialize(CK_VOID_PTR a)
{
    CK_C_INITIALIZE_ARGS_PTR args = reinterpret_cast<CK_C_INITIALIZE_ARGS_PTR>(a);
    st_logf("Initialize\n");
    
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
    st_logf("Finalize");
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
    st_logf("** GetInfo");
    
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
    st_logf("C_GetFunctionList\n");
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

    st_logf("slots: %d\n", *pulCount);
    
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
    st_logf("GetTokenInfo: slot: %d\n", slotID); 

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
      "471131");
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;

    if (!soft_token->logged() && std::getenv("SOFTPKCS11_FORCE_PIN")) {
        std::string pin = read_password();
        if (!soft_token->login(pin)) {
            return CKR_PIN_INCORRECT;
        }
    }
    
    if (!soft_token->logged())
      pInfo->flags |= CKF_LOGIN_REQUIRED;

    pInfo->ulMaxSessionCount = 5;
    pInfo->ulSessionCount = session_t::count();
    pInfo->ulMaxRwSessionCount = 5;
    pInfo->ulRwSessionCount = session_t::count();
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
    st_logf("GetMechanismList\n");

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
    
    auto session = session_t::create();
    *phSession = *session;
    
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    st_logf("CloseSession\n");
    session_t::destroy(hSession);
    return CKR_OK;
}



CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
//     struct session_state *state;

    st_logf("FindObjectsInit: Session: %d ulCount: %d\n", hSession, ulCount);

    auto session = session_t::find(hSession);
    if (session == session_t::end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!soft_token->logged()) {
        return CKR_USER_NOT_LOGGED_IN;
    }  
    
    print_attributes(pTemplate, ulCount);
    
//     VERIFY_SESSION_HANDLE(hSession, &state);

//     if (state->find.next_object != -1) {
//         application_error("application didn't do C_FindObjectsFinal\n");
//         find_object_final(state);
//     }
    if (ulCount) {
        
        Attributes attrs;
        
        for (CK_ULONG i = 0; i < ulCount; i++) {
            attrs[pTemplate[i].type] = pTemplate[i];
        }
        
        session->objects_iterator = soft_token->find_handles_iterator(attrs);
        st_logf(" == find initialized\n");
        
//         std::cout << "F1:" << session->objects_iterator() << std::endl;
//         std::cout << "F2:" << session->objects_iterator() << std::endl;
//         std::cout << "F3:" << session->objects_iterator() << std::endl;
        
//         CK_ULONG i;
//         size_t len;

//         print_attributes(pTemplate, ulCount);

//         state->find.attributes = 
//             calloc(1, ulCount * sizeof(state->find.attributes[0]));
//         if (state->find.attributes == NULL)
//             return CKR_DEVICE_MEMORY;
//         for (i = 0; i < ulCount; i++) {CKR_DEVICE_MEMORY
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
        st_logf(" == find all objects\n");
        session->objects_iterator = soft_token->handles_iterator();
    }

    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
          CK_OBJECT_HANDLE_PTR phObject,
          CK_ULONG ulMaxObjectCount,
          CK_ULONG_PTR pulObjectCount)
{
    st_logf("FindObjects Session: %d ulMaxObjectCount: %d\n", hSession, ulMaxObjectCount);

    if (ulMaxObjectCount == 0) {
        return CKR_ARGUMENTS_BAD;
    }
    
    auto session = session_t::find(hSession);
    if (session == session_t::end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    *pulObjectCount = 0;

    for(auto id = session->objects_iterator(); id != soft_token->handle_invalid(); id = session->objects_iterator()) {
        
        st_logf("found id %lu\n", id);
        
        *phObject++ = id;
        (*pulObjectCount)++;
        ulMaxObjectCount--;
        if (ulMaxObjectCount == 0) break;        
    }
    
    st_logf("  == pulObjectCount: %lu\n", *pulObjectCount);
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    st_logf("FindObjectsFinal\n");
    return CKR_OK;
}

const std::set<CK_ATTRIBUTE_TYPE> public_attributes = {
    CKA_CLASS, CKA_LABEL, CKA_APPLICATION, CKA_OBJECT_ID, CKA_MODIFIABLE,
    CKA_PRIVATE, CKA_TOKEN, CKA_DERIVE, CKA_LOCAL, CKA_KEY_GEN_MECHANISM, 
    CKA_ENCRYPT, CKA_VERIFY, CKA_KEY_TYPE, CKA_MODULUS, CKA_MODULUS_BITS, 
    CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_DECRYPT, CKA_SIGN, 
    CKA_SIGN_RECOVER, CKA_UNWRAP, CKA_EXTRACTABLE, CKA_NEVER_EXTRACTABLE,
    CKA_ALWAYS_AUTHENTICATE, CKA_ID, CKA_WRAP
};


CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    struct session_state *state;
    struct st_object *obj;
    CK_ULONG i;
    CK_RV ret;
    int j;

    st_logf("** GetAttributeValue: %lu %s ulCount: %d\n", hObject, soft_token->attributes(hObject)[CKA_LABEL].to_string().c_str(), ulCount);
    
    auto session = session_t::find(hSession);
    if (session == session_t::end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
   
    st_logf(" input ");
    print_attributes(pTemplate, ulCount);

    auto attrs = soft_token->attributes(hObject);
    
    for (i = 0; i < ulCount; i++) {
        if (public_attributes.find(pTemplate[i].type) == public_attributes.end()) {
            if (!soft_token->logged()) {
                return CKR_USER_NOT_LOGGED_IN;
            }              
        }
        
        auto it = attrs.find(pTemplate[i].type);
        
        if (it != attrs.end())
        {
            it->second.apply(pTemplate[i]);
        }
        
        if (pTemplate[i].type == CKA_VALUE) {
            const auto data = soft_token->read(hObject);
            if (pTemplate[i].pValue != NULL_PTR) {
                memcpy(pTemplate[i].pValue, data.c_str(), data.size());
            }
            pTemplate[i].ulValueLen = data.size();
        }
        else if (it == attrs.end()) {
            pTemplate[i].ulValueLen = (CK_ULONG)-1;
        }
    }
    
    st_logf(" output ");
    print_attributes(pTemplate, ulCount);
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    st_logf("Login\n");
    
    auto session = session_t::find(hSession);
    if (session == session_t::end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (soft_token->logged()) {
        if (std::getenv("SOFTPKCS11_FORCE_PIN")) {
            return CKR_OK;
        }
        return CKR_USER_ALREADY_LOGGED_IN;
    }  

    if (soft_token->login(std::string(reinterpret_cast<char*>(pPin), ulPinLen))) {
        return CKR_OK;    
    }
    else {
        return CKR_PIN_INCORRECT;  
    }
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    st_logf("SignInit\n");
    
    
    auto session = session_t::find(hSession);
    if (session == session_t::end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!soft_token->logged()) {
        return CKR_USER_NOT_LOGGED_IN;
    }  
    
    if (!soft_token->has_key(hKey)) {
        return CKR_KEY_HANDLE_INVALID;
    }
    
    const CK_BBOOL bool_true = CK_TRUE;
    
    if (!soft_token->check(hKey, {create_object(CKA_SIGN, bool_true)})) {
        return CKR_ARGUMENTS_BAD;
    }
    
    session->sign_key = hKey;
    session->sign_mechanism.mechanism = pMechanism->mechanism;
    session->sign_mechanism.ulParameterLen = pMechanism->ulParameterLen;
    memcpy(session->sign_mechanism.pParameter, pMechanism->pParameter, pMechanism->ulParameterLen);
    
    return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession,
       CK_BYTE_PTR pData,
       CK_ULONG ulDataLen,
       CK_BYTE_PTR pSignature,
       CK_ULONG_PTR pulSignatureLen)
{
    st_logf("Sign\n");
    
    auto session = session_t::find(hSession);
    if (session == session_t::end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!soft_token->logged()) {
        return CKR_USER_NOT_LOGGED_IN;
    }  

    if (session->sign_key == soft_token_t::handle_invalid()) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    
    if (pSignature == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }
    
    const auto signature = soft_token->sign(session->sign_key, session->sign_mechanism.mechanism, pData, ulDataLen);
    
    if (signature.size() > pulSignatureLen) {
        return CKR_BUFFER_TOO_SMALL;
    }
    
    std::copy(signature.begin(), signature.end(), pSignature);
    *pulSignatureLen = signature.size();
    
    return CKR_OK;
}


CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    st_logf("SignUpdate\n");

    auto session = session_t::find(hSession);
    if (session == session_t::end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    st_logf("C_SignFinal\n");

    auto session = session_t::find(hSession);
    if (session == session_t::end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    st_logf("Sign ok: CKR_OK size=%d\n", *pulSignatureLen);
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
    (void *)func_t<1>::not_supported, /* C_InitPIN */
    (void *)func_t<2>::not_supported, /* C_SetPIN */
    C_OpenSession,
    C_CloseSession,
        (void *)func_t<4>::not_supported, //C_CloseAllSessions,
        (void *)func_t<5>::not_supported, //C_GetSessionInfo,
    (void *)func_t<6>::not_supported, /* C_GetOperationState */
    (void *)func_t<7>::not_supported, /* C_SetOperationState */
    C_Login, //C_Login,
        (void *)func_t<9>::not_supported, //C_Logout,(void *)func_t::
    (void *)func_t<10>::not_supported, /* C_CreateObject */
    (void *)func_t<11>::not_supported, /* C_CopyObject */
    (void *)func_t<12>::not_supported, /* C_DestroyObject */
    (void *)func_t<13>::not_supported, /* C_GetObjectSize */
    C_GetAttributeValue,
    (void *)func_t<14>::not_supported, /* C_SetAttributeValue */
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
        (void *)func_t<16>::not_supported, //C_EncryptInit,
        (void *)func_t<17>::not_supported, //C_Encrypt,
        (void *)func_t<18>::not_supported, //C_EncryptUpdate,
        (void *)func_t<19>::not_supported, //C_EncryptFinal,
        (void *)func_t<20>::not_supported, //C_DecryptInit,
        (void *)func_t<21>::not_supported, //C_Decrypt,
        (void *)func_t<22>::not_supported, //C_DecryptUpdate,
        (void *)func_t<23>::not_supported, //C_DecryptFinal,
        (void *)func_t<24>::not_supported, //C_DigestInit,
    (void *)func_t<25>::not_supported, /* C_Digest */
    (void *)func_t<26>::not_supported, /* C_DigestUpdate */
    (void *)func_t<27>::not_supported, /* C_DigestKey */
    (void *)func_t<28>::not_supported, /* C_DigestFinal */
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    (void *)func_t<33>::not_supported, /* C_SignRecoverInit */
    (void *)func_t<34>::not_supported, /* C_SignRecover */
        (void *)func_t<35>::not_supported, //C_VerifyInit,
        (void *)func_t<36>::not_supported, //C_Verify,
        (void *)func_t<37>::not_supported, //C_VerifyUpdate,
        (void *)func_t<38>::not_supported, //C_VerifyFinal,
    (void *)func_t<39>::not_supported, /* C_VerifyRecoverInit */
    (void *)func_t<40>::not_supported, /* C_VerifyRecover */
    (void *)func_t<41>::not_supported, /* C_DigestEncryptUpdate */
    (void *)func_t<42>::not_supported, /* C_DecryptDigestUpdate */
    (void *)func_t<43>::not_supported, /* C_SignEncryptUpdate */
    (void *)func_t<44>::not_supported, /* C_DecryptVerifyUpdate */
    (void *)func_t<45>::not_supported, /* C_GenerateKey */
    (void *)func_t<46>::not_supported, /* C_GenerateKeyPair */
    (void *)func_t<47>::not_supported, /* C_WrapKey */
    (void *)func_t<48>::not_supported, /* C_UnwrapKey */
    (void *)func_t<49>::not_supported, /* C_DeriveKey */
    (void *)func_t<50>::not_supported, /* C_SeedRandom */
        (void *)func_t<51>::not_supported, //C_GenerateRandom,
    (void *)func_t<52>::not_supported, /* C_GetFunctionStatus */
    (void *)func_t<53>::not_supported, /* C_CancelFunction */
    (void *)func_t<54>::not_supported  /* C_WaitForSlotEvent */
};





}





