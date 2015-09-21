
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
#include "log.h"

#include "function_wrap.h"

#define ASSERT_PTR(ptr)\
    if (ptr == NULL_PTR) throw pkcs11_exception_t(CKR_ARGUMENTS_BAD, "Pointer " #ptr " must present.");
    
#define ASSERT_NOT_PTR(ptr)\
    if (ptr != NULL_PTR) throw pkcs11_exception_t(CKR_ARGUMENTS_BAD, "Pointer " #ptr " must present.");

std::auto_ptr<soft_token_t> soft_token;

template <int ID>
struct func_t {
    static CK_RV not_supported() {
        st_logf("function %d not supported\n", ID);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
};

struct exception_handler {
    template <typename Function, typename... Args>
    static CK_RV handle(Function f, Args... args) {
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


extern "C" {
  
CK_RV C_Initialize(CK_VOID_PTR a)
{
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
    LOG_G("%s slot:%d type:%d", __FUNCTION__, slotID, type);
    
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken(CK_SLOT_ID slotID,
        CK_UTF8CHAR_PTR pPin,
        CK_ULONG ulPinLen,
        CK_UTF8CHAR_PTR pLabel)
{
    LOG_G("%s slot:%d", __FUNCTION__, slotID);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID,
          CK_FLAGS flags,
          CK_VOID_PTR pApplication,
          CK_NOTIFY Notify,
          CK_SESSION_HANDLE_PTR phSession)
{
    LOG_G("%s slot:%d", __FUNCTION__, slotID);
    
    if (slotID != 1) return  CKR_SLOT_ID_INVALID;    
    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!soft_token->ready()) return CKR_TOKEN_NOT_PRESENT;
    
    *phSession = *session_t::create();
    
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
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
    LOG_G("%s session:%d", __FUNCTION__, hSession);

    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    if (!soft_token->ready()) return CKR_DEVICE_REMOVED;
    if (!soft_token->logged()) return CKR_USER_NOT_LOGGED_IN;

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    LOG_G("%s session:%d", __FUNCTION__, hSession);

    if (!soft_token.get()) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (session_t::find(hSession) == session_t::end()) return CKR_SESSION_HANDLE_INVALID;
    if (!soft_token->ready()) return CKR_DEVICE_REMOVED;
    if (!soft_token->logged()) return CKR_USER_NOT_LOGGED_IN;

    return CKR_OK;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
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
    WRAP_FUNCTION(CK_C_Initialize, exception_handler),
    WRAP_FUNCTION(CK_C_Finalize, exception_handler),
    WRAP_FUNCTION(CK_C_GetInfo, exception_handler),
    WRAP_FUNCTION(CK_C_GetFunctionList, exception_handler),
    WRAP_FUNCTION(CK_C_GetSlotList, exception_handler),
    WRAP_FUNCTION(CK_C_GetSlotInfo, exception_handler),
    WRAP_FUNCTION(CK_C_GetTokenInfo, exception_handler),
    WRAP_FUNCTION(CK_C_GetMechanismList, exception_handler),
    WRAP_FUNCTION(CK_C_GetMechanismInfo, exception_handler),
    WRAP_FUNCTION(CK_C_InitToken, exception_handler),
    WRAP_FUNCTION(CK_C_InitPIN, exception_handler),
    WRAP_NOT_IMPLEMENTED(CK_C_SetPIN),
    WRAP_FUNCTION(CK_C_OpenSession, exception_handler),
    WRAP_FUNCTION(CK_C_CloseSession, exception_handler),
        WRAP_NOT_IMPLEMENTED(CK_C_CloseAllSessions), //C_CloseAllSessions,
    WRAP_FUNCTION(CK_C_GetSessionInfo, exception_handler),
    WRAP_NOT_IMPLEMENTED(CK_C_GetOperationState), /* C_GetOperationState */
    WRAP_NOT_IMPLEMENTED(CK_C_SetOperationState), /* C_SetOperationState */
    WRAP_FUNCTION(CK_C_Login, exception_handler),
    WRAP_FUNCTION(CK_C_Logout, exception_handler),
    WRAP_FUNCTION(CK_C_CreateObject, exception_handler),
    WRAP_NOT_IMPLEMENTED(CK_C_CopyObject), /* C_CopyObject */
    WRAP_NOT_IMPLEMENTED(CK_C_DestroyObject), /* C_DestroyObject */
    WRAP_NOT_IMPLEMENTED(CK_C_GetObjectSize), /* C_GetObjectSize */
    WRAP_FUNCTION(CK_C_GetAttributeValue, exception_handler),
    WRAP_NOT_IMPLEMENTED(CK_C_SetAttributeValue), /* C_SetAttributeValue */
    WRAP_FUNCTION(CK_C_FindObjectsInit, exception_handler),
    WRAP_FUNCTION(CK_C_FindObjects, exception_handler),
    WRAP_FUNCTION(CK_C_FindObjectsFinal, exception_handler),
        WRAP_NOT_IMPLEMENTED(CK_C_EncryptInit), //C_EncryptInit,
        WRAP_NOT_IMPLEMENTED(CK_C_Encrypt), //C_Encrypt,
        WRAP_NOT_IMPLEMENTED(CK_C_EncryptUpdate), //C_EncryptUpdate,
        WRAP_NOT_IMPLEMENTED(CK_C_EncryptFinal), //C_EncryptFinal,
        
        WRAP_NOT_IMPLEMENTED(CK_C_DecryptInit), //C_DecryptInit,
        WRAP_NOT_IMPLEMENTED(CK_C_Decrypt), //C_Decrypt,
        WRAP_NOT_IMPLEMENTED(CK_C_DecryptUpdate), //C_DecryptUpdate,
        WRAP_NOT_IMPLEMENTED(CK_C_DecryptFinal), //C_DecryptFinal,
        
        WRAP_NOT_IMPLEMENTED(CK_C_DigestInit), //C_DigestInit,
    WRAP_NOT_IMPLEMENTED(CK_C_Digest), /* C_Digest */
    WRAP_NOT_IMPLEMENTED(CK_C_DigestUpdate), /* C_DigestUpdate */
    WRAP_NOT_IMPLEMENTED(CK_C_DigestKey), /* C_DigestKey */
    WRAP_NOT_IMPLEMENTED(CK_C_DigestFinal), /* C_DigestFinal */
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    WRAP_NOT_IMPLEMENTED(CK_C_SignRecoverInit), /* C_SignRecoverInit */
    WRAP_NOT_IMPLEMENTED(CK_C_SignRecover), /* C_SignRecover */
        WRAP_NOT_IMPLEMENTED(CK_C_VerifyInit), //C_VerifyInit,
        WRAP_NOT_IMPLEMENTED(CK_C_Verify), //C_Verify,
        WRAP_NOT_IMPLEMENTED(CK_C_VerifyUpdate), //C_VerifyUpdate,
        WRAP_NOT_IMPLEMENTED(CK_C_VerifyFinal), //C_VerifyFinal,
    WRAP_NOT_IMPLEMENTED(CK_C_VerifyRecoverInit), /* C_VerifyRecoverInit */
    WRAP_NOT_IMPLEMENTED(CK_C_VerifyRecover), /* C_VerifyRecover */
    
    WRAP_NOT_IMPLEMENTED(CK_C_DigestEncryptUpdate), /* C_DigestEncryptUpdate */
    WRAP_NOT_IMPLEMENTED(CK_C_DecryptDigestUpdate), /* C_DecryptDigestUpdate */
    WRAP_NOT_IMPLEMENTED(CK_C_SignEncryptUpdate), /* C_SignEncryptUpdate */
    WRAP_NOT_IMPLEMENTED(CK_C_DecryptVerifyUpdate), /* C_DecryptVerifyUpdate */
    WRAP_NOT_IMPLEMENTED(CK_C_GenerateKey), /* C_GenerateKey */
    WRAP_NOT_IMPLEMENTED(CK_C_GenerateKeyPair), /* C_GenerateKeyPair */
    WRAP_NOT_IMPLEMENTED(CK_C_WrapKey), /* C_WrapKey */
    WRAP_NOT_IMPLEMENTED(CK_C_UnwrapKey), /* C_UnwrapKey */
    WRAP_NOT_IMPLEMENTED(CK_C_DeriveKey), /* C_DeriveKey */
    WRAP_NOT_IMPLEMENTED(CK_C_SeedRandom), /* C_SeedRandom */
        WRAP_NOT_IMPLEMENTED(CK_C_GenerateRandom), //C_GenerateRandom,
    WRAP_NOT_IMPLEMENTED(CK_C_GetFunctionStatus), /* C_GetFunctionStatus */
    WRAP_NOT_IMPLEMENTED(CK_C_CancelFunction), /* C_CancelFunction */
    WRAP_NOT_IMPLEMENTED(CK_C_WaitForSlotEvent)  /* C_WaitForSlotEvent */
};


}





