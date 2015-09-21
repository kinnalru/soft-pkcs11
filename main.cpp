
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

#include <boost/fusion/container/map.hpp>
#include <boost/fusion/include/map.hpp>
#include <boost/fusion/include/at_key.hpp>
#include <boost/fusion/include/pair.hpp>

#include <boost/foreach.hpp>

#include "pkcs11/pkcs11u.h"
#include "pkcs11/pkcs11.h"

#include "tools.h"
#include "soft_token.h"
#include "exceptions.h"
#include "log.h"



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

template <typename Function, typename... Args>
CK_RV handle_exceptions(Function f, Args... args) {
    try {
        return f(args...);
    }
    catch (pkcs11_exception_t& e) {
        LOG("PKCS Error: %s", e.what());
        return e.rv;
    }
    catch (std::exception& e) {
        LOG("Error: %s", e.what());
        return CKR_FUNCTION_FAILED;
    }
    catch (...) {
        LOG("Unexpected Error");
        return CKR_GENERAL_ERROR;
    }
}

#define WRAP_FUNCTION(self, wrapper, ...)\
    static bool guard = true;\
    if (!guard) {\
        guard = true;\
        auto result = wrapper(self, ##__VA_ARGS__);\
        guard = false;\
        return result;\
    }
    
#define ASSERT_PTR(ptr)\
    if (ptr == NULL_PTR) throw pkcs11_exception_t(CKR_ARGUMENTS_BAD, "Pointer " #ptr " must present.");
    
#define ASSERT_NOT_PTR(ptr)\
    if (ptr != NULL_PTR) throw pkcs11_exception_t(CKR_ARGUMENTS_BAD, "Pointer " #ptr " must present.");

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
    ObjectsIterator objects_iterator;
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


template <typename Function>
Function wrap_function();

extern "C" {
  
CK_RV C_Initialize(CK_VOID_PTR a)
{
    WRAP_FUNCTION(C_Initialize, handle_exceptions, a);
    
    LOG_G("%s",__FUNCTION__);
    
    if (CK_C_INITIALIZE_ARGS_PTR args = reinterpret_cast<CK_C_INITIALIZE_ARGS_PTR>(a)) {
        return CKR_CANT_LOCK;
    }
    
    std::string rcfile;
    try {
        rcfile = std::string(std::getenv("SOFTPKCS11RC"));
    }
    catch(...) {
        const std::string home = std::string(std::getenv("HOME"));
        rcfile = home + "/.soft-token.rc";
    }

    if (soft_token.get()) return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    
    soft_token.reset(new soft_token_t(rcfile));
    
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR a)
{
    WRAP_FUNCTION(C_Finalize, handle_exceptions, a);
    
    LOG_G("%s",__FUNCTION__);
    ASSERT_NOT_PTR(a);
    
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

CK_RV C_GetInfo(CK_INFO_PTR info)
{
    WRAP_FUNCTION(C_GetInfo, handle_exceptions, info);
    
    LOG_G("%s",__FUNCTION__);
    ASSERT_PTR(info);
    
    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    
    memset(info, 17, sizeof(*info));
    info->cryptokiVersion.major = 1;
    info->cryptokiVersion.minor = 10;
    snprintf_fill((char *)info->manufacturerID, 
      sizeof(info->manufacturerID),
      ' ',
      "SoftToken");
    snprintf_fill((char *)info->libraryDescription, 
      sizeof(info->libraryDescription), ' ',
      "SoftToken");
    info->libraryVersion.major = 0;
    info->libraryVersion.minor = 1;

    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    WRAP_FUNCTION(C_GetSlotList, handle_exceptions, tokenPresent, pSlotList, pulCount);
    
    LOG_G("%s",__FUNCTION__);
    
    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;

    try {
        if (soft_token->ready()) {
            if (pSlotList) {
                pSlotList[0] = 1;
            }
            
            *pulCount = 1;
        }
        else {
            *pulCount = (tokenPresent) ? 0 : 1;
        }
    }
    catch(...) {
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    WRAP_FUNCTION(C_GetSlotInfo, handle_exceptions, slotID, pInfo);
    
    LOG_G("%s",__FUNCTION__);
    ASSERT_PTR(pInfo);
    
    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != 1) return  CKR_SLOT_ID_INVALID;
    
    memset(pInfo, 18, sizeof(*pInfo));

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
    WRAP_FUNCTION(C_GetTokenInfo, handle_exceptions, slotID, pInfo);
    
    LOG_G("%s",__FUNCTION__);
    ASSERT_PTR(pInfo);

    if (slotID != 1) return  CKR_SLOT_ID_INVALID;    
    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!soft_token->ready()) return CKR_TOKEN_NOT_PRESENT;

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
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_LOGIN_REQUIRED | CKF_PROTECTED_AUTHENTICATION_PATH;

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
    WRAP_FUNCTION(C_GetMechanismList, handle_exceptions, slotID, pMechanismList, pulCount);
    
    LOG_G("%s",__FUNCTION__);

    if (slotID != 1) return  CKR_SLOT_ID_INVALID;    
    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!soft_token->ready()) return CKR_TOKEN_NOT_PRESENT;
    
    if (pMechanismList == NULL_PTR) {
        *pulCount = 2;
        return CKR_OK;
    }

    if (*pulCount >= 2) {
        pMechanismList[0] = CKM_RSA_X_509;
        pMechanismList[1] = CKM_RSA_PKCS;
    }

    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    WRAP_FUNCTION(C_GetMechanismInfo, handle_exceptions, slotID, type, pInfo);
    
    LOG_G("%s slot:%d type:%d", __FUNCTION__, slotID, type);
    
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken(CK_SLOT_ID slotID,
        CK_UTF8CHAR_PTR pPin,
        CK_ULONG ulPinLen,
        CK_UTF8CHAR_PTR pLabel)
{
    WRAP_FUNCTION(C_InitToken, handle_exceptions, slotID, pPin, ulPinLen, pLabel);
    
    LOG_G("%s slot:%d", __FUNCTION__, slotID);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID,
          CK_FLAGS flags,
          CK_VOID_PTR pApplication,
          CK_NOTIFY Notify,
          CK_SESSION_HANDLE_PTR phSession)
{
    WRAP_FUNCTION(C_OpenSession, handle_exceptions, slotID, flags, pApplication, Notify, phSession);
     
    LOG_G("%s slot:%d", __FUNCTION__, slotID);
    
    if (slotID != 1) return  CKR_SLOT_ID_INVALID;    
    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!soft_token->ready()) return CKR_TOKEN_NOT_PRESENT;
    
    *phSession = *session_t::create();
    
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
//     WRAP_FUNCTION(C_CloseSession, handle_exceptions, hSession);
    
    LOG_G("%s session:%d", __FUNCTION__, hSession);
    
    LOG("s1")
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    
    LOG("s2")
    session_t::destroy(hSession);
    LOG("s3")
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    WRAP_FUNCTION(C_GetSessionInfo, handle_exceptions, hSession, pInfo);
    
    LOG_G("%s session:%d", __FUNCTION__, hSession);
    ASSERT_PTR(pInfo);
    
    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    if (!soft_token->ready()) return CKR_DEVICE_REMOVED;
    
    memset(pInfo, 20, sizeof(*pInfo));

    pInfo->slotID = 1;
    pInfo->state = (soft_token->logged())
        ? CKS_RW_USER_FUNCTIONS
        : CKS_RO_PUBLIC_SESSION;
    
    pInfo->flags = CKF_SERIAL_SESSION;
    if (soft_token->logged()) pInfo->flags |= CKF_SERIAL_SESSION;
    pInfo->ulDeviceError = 0;

    return CKR_OK;
}

const std::set<CK_ATTRIBUTE_TYPE> public_attributes = {
    CKA_CLASS, CKA_LABEL, CKA_APPLICATION, CKA_OBJECT_ID, CKA_MODIFIABLE,
    CKA_PRIVATE, CKA_TOKEN, CKA_DERIVE, CKA_LOCAL, CKA_KEY_GEN_MECHANISM, 
    CKA_ENCRYPT, CKA_VERIFY, CKA_KEY_TYPE, CKA_MODULUS, CKA_MODULUS_BITS, 
    CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_DECRYPT, CKA_SIGN, 
    CKA_SIGN_RECOVER, CKA_UNWRAP, CKA_EXTRACTABLE, CKA_NEVER_EXTRACTABLE,
    CKA_ALWAYS_AUTHENTICATE, CKA_ID, CKA_WRAP, CKA_CERTIFICATE_TYPE
};

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    WRAP_FUNCTION(C_FindObjectsInit, handle_exceptions, hSession, pTemplate, ulCount);
  
    LOG_G("%s session:%d ulCount%d", __FUNCTION__, hSession, ulCount);

    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    if (!soft_token->ready()) return CKR_DEVICE_REMOVED;
    
    if (!soft_token->logged()) {
        if (!soft_token->login(ask_password())) {
            return CKR_USER_NOT_LOGGED_IN;
        }
    }

    auto session = session_t::find(hSession);
    
    if (ulCount) {
        
        Attributes attrs;

        print_attributes(pTemplate, ulCount);
        
        for (CK_ULONG i = 0; i < ulCount; i++) {
            attrs[pTemplate[i].type] = pTemplate[i];
        }

        session->objects_iterator = soft_token->begin(attrs);
        LOG("Find initialized");
    } else {
        LOG("Find ALL initialized");
        session->objects_iterator = soft_token->begin();
    }

    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
          CK_OBJECT_HANDLE_PTR phObject,
          CK_ULONG ulMaxObjectCount,
          CK_ULONG_PTR pulObjectCount)
{
    WRAP_FUNCTION(C_FindObjects, handle_exceptions, hSession, phObject, ulMaxObjectCount, pulObjectCount);
    
    LOG_G("%s session:%d ulMaxObjectCount%d", __FUNCTION__, hSession, ulMaxObjectCount);

    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    if (!soft_token->ready()) return CKR_DEVICE_REMOVED;

    if (ulMaxObjectCount == 0) {
        return CKR_ARGUMENTS_BAD;
    }
    
    auto session = session_t::find(hSession);
    
    *pulObjectCount = 0;

    auto& it = session->objects_iterator;
    
    while(it != soft_token->end()) {
        LOG("Found id %lu", it->first);
        
        *phObject++ = it->first;
        (*pulObjectCount)++;
        ulMaxObjectCount--;
        ++it;
        
        if (ulMaxObjectCount == 0) break;        
    }
    
    LOG("Return %lu objects", *pulObjectCount);
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    LOG("F1 %d", hSession);
    WRAP_FUNCTION(C_FindObjectsFinal, handle_exceptions, hSession);
    
    LOG("F2 %d", hSession);

    LOG_G("%s session:%d", __FUNCTION__, hSession);
    
    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    
    LOG("F3 %d", hSession);
    
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    
    LOG("F4 %d", hSession);
    if (!soft_token->ready()) return CKR_DEVICE_REMOVED;
    
    LOG("F5 %d", hSession);
    
    session_t::find(hSession)->objects_iterator = soft_token->end();
    
    LOG("F6 %d", hSession);
    
    return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    WRAP_FUNCTION(C_GetAttributeValue, handle_exceptions, hSession, hObject, pTemplate, ulCount);
    
    LOG_G("%s session:%d handle:%lu %s ulCount:%d", __FUNCTION__, hSession, hObject, soft_token->attributes(hObject)[CKA_LABEL].to_string().c_str(), ulCount);
    
    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    if (!soft_token->ready()) return CKR_DEVICE_REMOVED;
    if (!soft_token->has_object(hObject)) return CKR_OBJECT_HANDLE_INVALID;
    
    {
        LOG_G("Input");
        print_attributes(pTemplate, ulCount);
    }

    auto session = session_t::find(hSession);
    auto attrs = soft_token->attributes(hObject);
    
    //TODO handle CKR_BUFFER_TOO_SMALL
    
    for (int i = 0; i < ulCount; i++) {
        if (public_attributes.find(pTemplate[i].type) == public_attributes.end()) {
          if (!soft_token->logged()) {
              if (!soft_token->login(ask_password())) {
                  return CKR_USER_NOT_LOGGED_IN;
              }
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
    
    {
        LOG_G("Output");
        print_attributes(pTemplate, ulCount);
    }
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    WRAP_FUNCTION(C_Login, handle_exceptions, hSession, userType, pPin, ulPinLen);
  
    LOG_G("%s session:%d", __FUNCTION__, hSession);
    
    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    if (!soft_token->ready()) return CKR_DEVICE_REMOVED;
    if (soft_token->logged()) return CKR_USER_ALREADY_LOGGED_IN;

    
    std::string pin;
    
    if (pPin == NULL_PTR) {
        pin = ask_password();
    }
    else {
        pin = std::string(reinterpret_cast<char*>(pPin), ulPinLen);
    }
    
    if (soft_token->login(pin)) {
        return CKR_OK;    
    }
    else {
        if (soft_token->ssh_agent()) return CKR_OK;
        return CKR_PIN_INCORRECT;  
    }
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    WRAP_FUNCTION(C_Logout, handle_exceptions, hSession);
    
    LOG_G("%s session:%d", __FUNCTION__, hSession);
    
    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    if (!soft_token->ready()) return CKR_DEVICE_REMOVED;
    if (!soft_token->logged()) return CKR_USER_NOT_LOGGED_IN;
    
    soft_token->logout();
    
    return CKR_OK;    
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    WRAP_FUNCTION(C_SignInit, handle_exceptions, hSession, pMechanism, hKey);
    
    LOG_G("%s session:%d", __FUNCTION__, hSession);

    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    if (!soft_token->ready()) return CKR_DEVICE_REMOVED;
    if (!soft_token->logged()) return CKR_USER_NOT_LOGGED_IN;
    
    if (!soft_token->has_object(hKey)) return CKR_KEY_HANDLE_INVALID;
    
    const CK_BBOOL bool_true = CK_TRUE;
    
    if (!soft_token->check(hKey, {create_object(CKA_SIGN, bool_true)})) {
        return CKR_ARGUMENTS_BAD;
    }
    
    auto session = session_t::find(hSession);
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
    WRAP_FUNCTION(C_Sign, handle_exceptions, hSession, pData, ulDataLen, pSignature, pulSignatureLen);
    
    LOG_G("%s session:%d", __FUNCTION__, hSession);
    ASSERT_PTR(pData);
    
    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    if (!soft_token->ready()) return CKR_DEVICE_REMOVED;
    if (!soft_token->logged()) return CKR_USER_NOT_LOGGED_IN;
    
    auto session = session_t::find(hSession);

    if (session->sign_key == soft_token_t::handle_invalid()) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    
    const auto signature = soft_token->sign(session->sign_key, session->sign_mechanism.mechanism, pData, ulDataLen);
    if (signature.size() > *pulSignatureLen) {
        return CKR_BUFFER_TOO_SMALL;
    }
    
    ASSERT_PTR(pSignature);
    std::copy(signature.begin(), signature.end(), pSignature);
    *pulSignatureLen = signature.size();
    
    return CKR_OK;
}


CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    WRAP_FUNCTION(C_SignUpdate, handle_exceptions, hSession, pPart, ulPartLen);
    
    LOG_G("%s session:%d", __FUNCTION__, hSession);

    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    if (!soft_token->ready()) return CKR_DEVICE_REMOVED;
    if (!soft_token->logged()) return CKR_USER_NOT_LOGGED_IN;

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    WRAP_FUNCTION(C_SignFinal, handle_exceptions, hSession, pSignature, pulSignatureLen);
    
    LOG_G("%s session:%d", __FUNCTION__, hSession);

    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    if (!soft_token->ready()) return CKR_DEVICE_REMOVED;
    if (!soft_token->logged()) return CKR_USER_NOT_LOGGED_IN;

    return CKR_OK;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    WRAP_FUNCTION(C_CreateObject, handle_exceptions, hSession, pTemplate, ulCount, phObject);

    LOG_G("%s session:%d", __FUNCTION__, hSession);
    
    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    if (!soft_token->ready()) return CKR_DEVICE_REMOVED;
    
    if (!soft_token->logged()) {
        if (!soft_token->login(ask_password())) {
            return CKR_USER_NOT_LOGGED_IN;
        }
    } 
    

    
    std::string label;
    std::vector<unsigned char> value;
    
    std::string suf;
    
    Attributes attrs;
    for (CK_ULONG i = 0; i < ulCount; i++) {
        attrs[pTemplate[i].type] = pTemplate[i];
    }  
   
    for (int i = 0; i < ulCount; i++) {
        if(pTemplate[i].type == CKA_VALUE) {
            value = attribute_t(pTemplate[i]).to_bytes();
        }
        if(pTemplate[i].type == CKA_LABEL) {
            label = attribute_t(pTemplate[i]).to_string();
        }
        if(pTemplate[i].type == CKA_CLASS) {
            CK_OBJECT_CLASS klass = *((CK_OBJECT_CLASS*)pTemplate[i].pValue);
            
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
    
    *phObject = soft_token->write(label, value, attrs);
    
    LOG("Object created: %lu", *phObject);
    print_attributes(soft_token->attributes(*phObject));
    return CKR_OK;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

extern CK_FUNCTION_LIST funcs;

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    LOG_G("%s",__FUNCTION__);
    *ppFunctionList = &funcs;
    return CKR_OK;
}


CK_FUNCTION_LIST funcs = {
    { 2, 11 },
    wrap_function<CK_C_Initialize>(),
    wrap_function<CK_C_Finalize>(),
    wrap_function<CK_C_GetInfo>(),
    wrap_function<CK_C_GetFunctionList>(),
    wrap_function<CK_C_GetSlotList>(),
    wrap_function<CK_C_GetSlotInfo>(),
    wrap_function<CK_C_GetTokenInfo>(),
    wrap_function<CK_C_GetMechanismList>(),
    wrap_function<CK_C_GetMechanismInfo>(),
    wrap_function<CK_C_InitToken>(),
    wrap_function<CK_C_InitPIN>(),
    reinterpret_cast<CK_C_SetPIN>(func_t<2>::not_supported), /* C_SetPIN */
    C_OpenSession,
    C_CloseSession,
        reinterpret_cast<CK_C_CloseAllSessions>(func_t<4>::not_supported), //C_CloseAllSessions,
    wrap_function<CK_C_GetSessionInfo>(),
    reinterpret_cast<CK_C_GetOperationState>(func_t<6>::not_supported), /* C_GetOperationState */
    reinterpret_cast<CK_C_SetOperationState>(func_t<7>::not_supported), /* C_SetOperationState */
    wrap_function<CK_C_Login>(),
    wrap_function<CK_C_Logout>(),
    wrap_function<CK_C_CreateObject>(),
    reinterpret_cast<CK_C_CopyObject>(func_t<11>::not_supported), /* C_CopyObject */
    reinterpret_cast<CK_C_DestroyObject>(func_t<12>::not_supported), /* C_DestroyObject */
    reinterpret_cast<CK_C_GetObjectSize>(func_t<13>::not_supported), /* C_GetObjectSize */
    wrap_function<CK_C_GetAttributeValue>(),
    reinterpret_cast<CK_C_SetAttributeValue>(func_t<14>::not_supported), /* C_SetAttributeValue */
    wrap_function<CK_C_FindObjectsInit>(),
    wrap_function<CK_C_FindObjects>(),
    wrap_function<CK_C_FindObjectsFinal>(),
//     C_FindObjectsFinal,
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

#define FUSION_MAX_MAP_SIZE 30
#define FUSION_MAX_VECTOR_SIZE 30

#include <boost/fusion/include/make_map.hpp>
#include <boost/preprocessor.hpp>

template <typename Function>
Function rvcast(Function f) {return f;}

unsigned constexpr const_hash(char const *input) {
    return *input ?
      static_cast<unsigned int>(*input) + 33 * const_hash(input + 1) :
      5381;
}

template <long long T>
struct tag_s {};

//#define __ADD_TAG(r, data, elem) (BOOST_PP_CAT(CK_, elem))
#define __ADD_TAG(r, data, elem) (tag_s<const_hash(BOOST_STRINGIZE(BOOST_PP_CAT(CK_, elem)))>)

#define __ADD_RVCAST(r, data, elem) (rvcast(elem))

#define __ADD_PRINT(r, data, elem) (rvcast(elem))

#define TUPLE (\
    C_Initialize, C_Finalize,\
    C_GetInfo, C_GetFunctionList, C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo,\
    C_GetMechanismList, C_GetMechanismInfo,\
    C_InitToken, C_InitPIN,\
    C_OpenSession, C_CloseSession,\
    C_GetSessionInfo,\
    C_Login, C_Logout,\
    C_CreateObject,\
    C_GetAttributeValue,\
    C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal,\
    C_SignInit, C_Sign, C_SignUpdate, C_SignFinal\
)

#define __TUPLE_SEQ BOOST_PP_TUPLE_TO_SEQ(TUPLE)

#define __SEQ_WITH_CK BOOST_PP_SEQ_FOR_EACH(__ADD_TAG, 0, __TUPLE_SEQ)
#define __SEQ_WITH_RVCAST BOOST_PP_SEQ_FOR_EACH(__ADD_RVCAST, 0, __TUPLE_SEQ)

#define __TUPLE_WITH_CK BOOST_PP_SEQ_TO_TUPLE(__SEQ_WITH_CK)
#define __TUPLE_WITH_RVCAST BOOST_PP_SEQ_TO_TUPLE(__SEQ_WITH_RVCAST)


#define FUNCTION_TYPES BOOST_PP_TUPLE_REM_CTOR(BOOST_PP_TUPLE_SIZE(__TUPLE_WITH_CK), __TUPLE_WITH_CK)
#define FUNCTION_CASTS BOOST_PP_TUPLE_REM_CTOR(BOOST_PP_TUPLE_SIZE(__TUPLE_WITH_RVCAST), __TUPLE_WITH_RVCAST)

#include <boost/fusion/algorithm/iteration/for_each.hpp>
#include <boost/fusion/include/for_each.hpp>


const auto functions_c = boost::fusion::make_map<FUNCTION_TYPES>(FUNCTION_CASTS);

#define TTT(elem) BOOST_STRINGIZE(tag_s<const_hash(#elem)>)

static const bool b = [](){

    std::cerr << "test: " << TTT(test) << std::endl;;
  
    std::cerr << "h1:" << const_hash("h1") << std::endl;
    std::cerr << "h2:" << const_hash("h2") << std::endl;
    std::cerr << "h1:" << const_hash("h1") << std::endl;
  
  LOG("FindOF: [%lu]", C_FindObjectsFinal);  
//   LOG("FindOFW: [%lu]", boost::fusion::at_key<CK_C_FindObjectsFinal>(functions_c));  
  
//   boost::fusion::for_each(functions_c, increment());
  
//   LOG("FindOFW: [%lu]", boost::fusion::at_key<CK_C_FindObjectsFinal>(functions_c));  
  
  return true;
}();



template <typename Function, typename ...Args>
CK_RV wrap_function_impl(Args... args) {
//     return boost::fusion::at_key<Function>(functions_c)(args...);
  return 0;
}

template <typename Function>
Function wrap_function() {
  return static_cast<Function>(wrap_function_impl<Function>);
}



