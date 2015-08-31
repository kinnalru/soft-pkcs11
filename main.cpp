
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
#include "exceptions.h"


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
    
    static void clear() {
        return _sessions.clear();
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
    st_logf(" ** C_Initialize\n");

    
    std::string rcfile;
    try {
        rcfile = std::string(std::getenv("SOFTPKCS11RC"));
    }
    catch(...) {
        const std::string home = std::string(std::getenv("HOME"));
        rcfile = home + "/.soft-token.rc";
    }

    try {
      soft_token.reset(new soft_token_t(rcfile));
    }
    catch(const std::exception& e) {
        st_logf("Initializing error: %s\n", e.what());
        return CKR_GENERAL_ERROR;
    }
    
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR args)
{
    st_logf(" ** C_Finalize\n");
    session_t::clear();
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
    st_logf(" ** C_GetInfo\n");
    
    if (!soft_token.get()) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    memset(args, 17, sizeof(*args));
    args->cryptokiVersion.major = 1;
    args->cryptokiVersion.minor = 10;
    snprintf_fill((char *)args->manufacturerID, 
      sizeof(args->manufacturerID),
      ' ',
      "SoftToken");
    snprintf_fill((char *)args->libraryDescription, 
      sizeof(args->libraryDescription), ' ',
      "SoftToken");
    args->libraryVersion.major = 0;
    args->libraryVersion.minor = 1;

    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR   pulCount)
{
    st_logf(" ** C_GetSlotList\n");

    if (soft_token->ready()) {
        if (pSlotList) {
            pSlotList[0] = 1;
        }
        
        *pulCount = 1;
    }
    else {
        *pulCount = 0;
    }

    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    st_logf(" ** C_GetSlotInfo\n");

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
    
    pInfo->flags = CKF_REMOVABLE_DEVICE;
    if (soft_token->ready()) pInfo->flags |= CKF_TOKEN_PRESENT;
    
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;

    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    st_logf(" ** C_GetTokenInfo\n"); 
    
    if (!soft_token->ready()) {
        return CKR_TOKEN_NOT_PRESENT;
    }

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
      soft_token->full_name().c_str());
    snprintf_fill((char *)pInfo->serialNumber, 
      sizeof(pInfo->serialNumber),
      ' ',
      "391137");
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;
    pInfo->flags |= CKF_LOGIN_REQUIRED;
    
//     if (!soft_token->logged() && std::getenv("SOFTPKCS11_FORCE_PIN")) {
//         CKF_PROTECTED_AUTHENTICATION_PATH
//         std::string pin = read_password();
//         if (!soft_token->login(pin)) {
//             return CKR_PIN_INCORRECT;
//         }
//     }

    pInfo->ulMaxSessionCount = 5;
    pInfo->ulSessionCount = session_t::count();
    pInfo->ulMaxRwSessionCount = 5;
    pInfo->ulRwSessionCount = session_t::count();
    pInfo->ulMaxPinLen = 1024;
    pInfo->ulMinPinLen = 0;
    pInfo->ulTotalPublicMemory = 47120;
    pInfo->ulFreePublicMemory = 47110;
    pInfo->ulTotalPrivateMemory = 47140;
    pInfo->ulFreePrivateMemory = 47130;
    pInfo->hardwareVersion.major = 2;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 2;
    pInfo->firmwareVersion.minor = 0;

    return CKR_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    st_logf(" ** C_GetMechanismList\n");

    if (!soft_token->ready()) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    
    *pulCount = 2;
    if (pMechanismList == NULL_PTR) return CKR_OK;

    pMechanismList[0] = CKM_RSA_X_509;
    pMechanismList[1] = CKM_RSA_PKCS;

    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    st_logf(" ** C_GetMechanismInfo: slot %d type: %d\n", (int)slotID, (int)type);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken(CK_SLOT_ID slotID,
        CK_UTF8CHAR_PTR pPin,
        CK_ULONG ulPinLen,
        CK_UTF8CHAR_PTR pLabel)
{
    st_logf(" ** C_InitToken: slot %d\n", (int)slotID);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID,
          CK_FLAGS flags,
          CK_VOID_PTR pApplication,
          CK_NOTIFY Notify,
          CK_SESSION_HANDLE_PTR phSession)
{
    int i;

    st_logf(" ** C_OpenSession: slot: %d\n", (int)slotID);
    
    if (!soft_token->ready()) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    
    auto session = session_t::create();
    *phSession = *session;
    
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    st_logf(" ** C_CloseSession\n");
    
    session_t::destroy(hSession);
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    st_logf(" ** C_GetSessionInfo\n");
    
    if (!soft_token->ready()) {
        return CKR_DEVICE_REMOVED;
    }
    
    auto session = session_t::find(hSession);
    if (session == session_t::end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    memset(pInfo, 20, sizeof(*pInfo));

    pInfo->slotID = 1;
    if (soft_token->logged()) {
        pInfo->state = CKS_RO_USER_FUNCTIONS;
    }
    else {
        pInfo->state = CKS_RO_PUBLIC_SESSION;
    }
    
    pInfo->flags = CKF_SERIAL_SESSION;
    pInfo->ulDeviceError = 0;

    return CKR_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    st_logf(" ** C_FindObjectsInit: Session: %d ulCount: %d\n", hSession, ulCount);

    if (!soft_token->ready()) {
        return CKR_DEVICE_REMOVED;
    }
    
    auto session = session_t::find(hSession);
    if (session == session_t::end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!soft_token->logged()) {
        if (!soft_token->ssh_agent()) {
            return CKR_USER_NOT_LOGGED_IN;
        }
    }  
    
    print_attributes(pTemplate, ulCount);
    
    if (ulCount) {
        
        Attributes attrs;
        
        for (CK_ULONG i = 0; i < ulCount; i++) {
            attrs[pTemplate[i].type] = pTemplate[i];
        }
        
        session->objects_iterator = soft_token->find_handles_iterator(attrs);
        st_logf(" == find initialized\n");
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
    st_logf(" ** C_FindObjects Session: %d ulMaxObjectCount: %d\n", hSession, ulMaxObjectCount);

    if (!soft_token->ready()) {
        return CKR_DEVICE_REMOVED;
    }

    if (ulMaxObjectCount == 0) {
        return CKR_ARGUMENTS_BAD;
    }
    
    auto session = session_t::find(hSession);
    if (session == session_t::end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    *pulObjectCount = 0;

    try {
        for(auto id = session->objects_iterator(); id != soft_token->handle_invalid(); id = session->objects_iterator()) {
            
            st_logf("found id %lu\n", id);
            
            *phObject++ = id;
            (*pulObjectCount)++;
            ulMaxObjectCount--;
            if (ulMaxObjectCount == 0) break;        
        }
    }
    catch(...) {
      
    }
    
    st_logf("  == pulObjectCount: %lu\n", *pulObjectCount);
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    st_logf(" ** C_FindObjectsFinal\n");
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

    st_logf("** C_GetAttributeValue: %lu %s ulCount: %d\n", hObject, soft_token->attributes(hObject)[CKA_LABEL].to_string().c_str(), ulCount);
    
    if (!soft_token->ready()) {
        return CKR_DEVICE_REMOVED;
    }

    
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
            
            try {
                const auto data = soft_token->read(hObject);
                if (pTemplate[i].pValue != NULL_PTR) {
                    memcpy(pTemplate[i].pValue, data.c_str(), data.size());
                }
                pTemplate[i].ulValueLen = data.size();
            }
            catch(const pkcs11_exception_t& e) {
                st_logf("read exception: %s\n", e.what());
                return e.rv;
            }
            catch(const std::exception& e) {
                st_logf("read exception: %s\n", e.what());
                return CKR_DEVICE_REMOVED;
            }
            
        }
        else if (it == attrs.end()) {
            pTemplate[i].ulValueLen = (CK_ULONG)-1;
        }
    }
    
    st_logf(" output ");
    //print_attributes(pTemplate, ulCount);
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    st_logf(" ** C_Login\n");
    
    if (!soft_token->ready()) {
        return CKR_DEVICE_REMOVED;
    }
    
    auto session = session_t::find(hSession);
    if (session == session_t::end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (soft_token->logged()) {
//         if (std::getenv("SOFTPKCS11_FORCE_PIN")) {
//             return CKR_OK;
//         }
        return CKR_USER_ALREADY_LOGGED_IN;
    }  
    st_logf(" NOT\n");

    if (soft_token->login(std::string(reinterpret_cast<char*>(pPin), ulPinLen))) {
        st_logf(" OK\n");
        return CKR_OK;    
    }
    else {
        if (soft_token->ssh_agent()) return CKR_OK;
        st_logf(" ERR\n");
        return CKR_PIN_INCORRECT;  
    }
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    st_logf(" ** C_Logout\n");
    
    auto session = session_t::find(hSession);
    if (session == session_t::end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    soft_token->logout();
    
    return CKR_OK;    
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    st_logf(" ** C_SignInit\n");

    if (!soft_token->ready()) {
        return CKR_DEVICE_REMOVED;
    }
    
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
    
//     if (soft_token->ssh_agent()) return CKR_KEY_HANDLE_INVALID;
    
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
    st_logf(" ** C_Sign\n");
    
    if (!soft_token->ready()) {
        return CKR_DEVICE_REMOVED;
    }
    
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

    try {
        const auto signature = soft_token->sign(session->sign_key, session->sign_mechanism.mechanism, pData, ulDataLen);
        if (signature.size() > *pulSignatureLen) {
            return CKR_BUFFER_TOO_SMALL;
        }
        
        std::copy(signature.begin(), signature.end(), pSignature);
        *pulSignatureLen = signature.size();
    }
    catch(const pkcs11_exception_t& e) {
        st_logf("sign error: %s\n", e.what());
        return e.rv;
    }
    catch(const std::exception& e) {
        st_logf("sign error: %s\n", e.what());
//         if (soft_token->ssh_agent()) return CKR_OPERATION_NOT_INITIALIZED;
        return CKR_FUNCTION_FAILED;
    }
    
    return CKR_OK;
}


CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    st_logf("C_SignUpdate\n");

    if (!soft_token->ready()) {
        return CKR_DEVICE_REMOVED;
    }
    
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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/md5.h>

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    st_logf("C_CreateObject\n");
    
    if (!soft_token->ready()) {
        return CKR_DEVICE_REMOVED;
    }
    
    auto session = session_t::find(hSession);
    if (session == session_t::end()) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!soft_token->logged()) {
        return CKR_USER_NOT_LOGGED_IN;
    } 
    
    CK_OBJECT_HANDLE id = soft_token_t::handle_invalid();
    
    std::string label;
    std::vector<unsigned char> value;
    
    std::string suf;
   
    for (int i = 0; i < ulCount; i++) {
        if(pTemplate[i].type == CKA_VALUE) {
            value = attribute_t(pTemplate[i]).to_bytes();
        }
        if(pTemplate[i].type == CKA_LABEL) {
            label = attribute_t(pTemplate[i]).to_string();
        }
        if(pTemplate[i].type == CKA_CLASS) {
            CK_OBJECT_CLASS klass = *((CK_OBJECT_CLASS*)pTemplate[i].pValue);
            
            Attributes attrs;
            for (CK_ULONG i = 0; i < ulCount; i++) {
                attrs[pTemplate[i].type] = pTemplate[i];
            }            
            if (klass == CKO_PUBLIC_KEY) {
                value = soft_token->create_key(klass, attrs);
                suf = ".pub";
            }
            else if(klass == CKO_PRIVATE_KEY) {
                value = soft_token->create_key(klass, attrs);
            }
        }
    }
    
    if (label.empty()) {
        return CKR_TEMPLATE_INCOMPLETE;
    }

    label = label + suf;
    
    print_attributes(pTemplate, ulCount);
    st_logf("WRITE: %s  -  %s\n", label.c_str(), value.data());
    
    try {
      id = soft_token->write(label, value);    
    }
    catch(const pkcs11_exception_t& e) {
        st_logf("write error: %s\n", e.what());
        return e.rv;
    }
    catch(const std::exception& e) {
        st_logf("write error: %s\n", e.what());
//         if (soft_token->ssh_agent()) return CKR_OPERATION_NOT_INITIALIZED;
        return CKR_FUNCTION_FAILED;
    }

    
    if (id != soft_token_t::handle_invalid()) {
        *phObject = id;
        st_logf("object created %lu\n", id);
        return CKR_OK;
    }
    
    return CKR_ARGUMENTS_BAD;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

extern CK_FUNCTION_LIST funcs;

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    st_logf("C_GetFunctionList\n");
    *ppFunctionList = &funcs;
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
    C_InitPIN,
    reinterpret_cast<CK_C_SetPIN>(func_t<2>::not_supported), /* C_SetPIN */
    C_OpenSession,
    C_CloseSession,
        reinterpret_cast<CK_C_CloseAllSessions>(func_t<4>::not_supported), //C_CloseAllSessions,
    C_GetSessionInfo,
    reinterpret_cast<CK_C_GetOperationState>(func_t<6>::not_supported), /* C_GetOperationState */
    reinterpret_cast<CK_C_SetOperationState>(func_t<7>::not_supported), /* C_SetOperationState */
    C_Login,
    C_Logout,
    C_CreateObject,
    reinterpret_cast<CK_C_CopyObject>(func_t<11>::not_supported), /* C_CopyObject */
    reinterpret_cast<CK_C_DestroyObject>(func_t<12>::not_supported), /* C_DestroyObject */
    reinterpret_cast<CK_C_GetObjectSize>(func_t<13>::not_supported), /* C_GetObjectSize */
    C_GetAttributeValue,
    reinterpret_cast<CK_C_SetAttributeValue>(func_t<14>::not_supported), /* C_SetAttributeValue */
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
        reinterpret_cast<CK_C_EncryptInit>(func_t<16>::not_supported), //C_EncryptInit,
        reinterpret_cast<CK_C_Encrypt>(func_t<17>::not_supported), //C_Encrypt,
        reinterpret_cast<CK_C_EncryptUpdate>(func_t<18>::not_supported), //C_EncryptUpdate,
        reinterpret_cast<CK_C_EncryptFinal>(func_t<19>::not_supported), //C_EncryptFinal,
        
        reinterpret_cast<CK_C_DecryptInit>(func_t<20>::not_supported), //C_DecryptInit,
        reinterpret_cast<CK_C_Decrypt>(func_t<21>::not_supported), //C_Decrypt,
        reinterpret_cast<CK_C_DecryptUpdate>(func_t<22>::not_supported), //C_DecryptUpdate,
        reinterpret_cast<CK_C_DecryptFinal>(func_t<23>::not_supported), //C_DecryptFinal,
        
        reinterpret_cast<CK_C_DigestInit>(func_t<24>::not_supported), //C_DigestInit,
    reinterpret_cast<CK_C_Digest>(func_t<25>::not_supported), /* C_Digest */
    reinterpret_cast<CK_C_DigestUpdate>(func_t<26>::not_supported), /* C_DigestUpdate */
    reinterpret_cast<CK_C_DigestKey>(func_t<27>::not_supported), /* C_DigestKey */
    reinterpret_cast<CK_C_DigestFinal>(func_t<28>::not_supported), /* C_DigestFinal */
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    reinterpret_cast<CK_C_SignRecoverInit>(func_t<33>::not_supported), /* C_SignRecoverInit */
    reinterpret_cast<CK_C_SignRecover>(func_t<34>::not_supported), /* C_SignRecover */
        reinterpret_cast<CK_C_VerifyInit>(func_t<35>::not_supported), //C_VerifyInit,
        reinterpret_cast<CK_C_Verify>(func_t<36>::not_supported), //C_Verify,
        reinterpret_cast<CK_C_VerifyUpdate>(func_t<37>::not_supported), //C_VerifyUpdate,
        reinterpret_cast<CK_C_VerifyFinal>(func_t<38>::not_supported), //C_VerifyFinal,
    reinterpret_cast<CK_C_VerifyRecoverInit>(func_t<39>::not_supported), /* C_VerifyRecoverInit */
    reinterpret_cast<CK_C_VerifyRecover>(func_t<40>::not_supported), /* C_VerifyRecover */
    
    reinterpret_cast<CK_C_DigestEncryptUpdate>(func_t<41>::not_supported), /* C_DigestEncryptUpdate */
    reinterpret_cast<CK_C_DecryptDigestUpdate>(func_t<42>::not_supported), /* C_DecryptDigestUpdate */
    reinterpret_cast<CK_C_SignEncryptUpdate>(func_t<43>::not_supported), /* C_SignEncryptUpdate */
    reinterpret_cast<CK_C_DecryptVerifyUpdate>(func_t<44>::not_supported), /* C_DecryptVerifyUpdate */
    reinterpret_cast<CK_C_GenerateKey>(func_t<45>::not_supported), /* C_GenerateKey */
    reinterpret_cast<CK_C_GenerateKeyPair>(func_t<46>::not_supported), /* C_GenerateKeyPair */
    reinterpret_cast<CK_C_WrapKey>(func_t<47>::not_supported), /* C_WrapKey */
    reinterpret_cast<CK_C_UnwrapKey>(func_t<48>::not_supported), /* C_UnwrapKey */
    reinterpret_cast<CK_C_DeriveKey>(func_t<49>::not_supported), /* C_DeriveKey */
    reinterpret_cast<CK_C_SeedRandom>(func_t<50>::not_supported), /* C_SeedRandom */
        reinterpret_cast<CK_C_GenerateRandom>(func_t<51>::not_supported), //C_GenerateRandom,
    reinterpret_cast<CK_C_GetFunctionStatus>(func_t<52>::not_supported), /* C_GetFunctionStatus */
    reinterpret_cast<CK_C_CancelFunction>(func_t<53>::not_supported), /* C_CancelFunction */
    reinterpret_cast<CK_C_WaitForSlotEvent>(func_t<54>::not_supported)  /* C_WaitForSlotEvent */
};





}





