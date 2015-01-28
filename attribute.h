#ifndef ST_ATTRIBUTE_H
#define ST_ATTRIBUTE_H

#include <memory>

#include "pkcs11/pkcs11u.h"
#include "pkcs11/pkcs11.h"

struct attribute_t {

    attribute_t() {}
    attribute_t(const CK_ATTRIBUTE& other);
    
    
//     attribute_t(CK_ATTRIBUTE_TYPE type, CK_ULONG size);
    
    attribute_t(CK_ATTRIBUTE_TYPE type, CK_VOID_PTR value, CK_ULONG size);
    
    attribute_t(CK_ATTRIBUTE_TYPE type, const std::string& string);
    
    template <typename T>
    attribute_t(CK_ATTRIBUTE_TYPE type, const T& object) {
        CK_ATTRIBUTE other;
        other.type = type;
        other.pValue = const_cast<T*>(&object); 
        other.ulValueLen = sizeof(object);
        
        this->operator=(other);
    }
    
    bool operator==(const attribute_t& other) const;
    bool operator!=(const attribute_t& other) const;
    
    attribute_t& operator=(const CK_ATTRIBUTE& other);
    
    void apply(CK_ATTRIBUTE& dst) const;
    
    const CK_ATTRIBUTE* operator->() const {
        return &attr_;
    }
    
    const std::string to_string() const {
        return std::string(reinterpret_cast<char*>(attr_.pValue), attr_.ulValueLen);
    }
    
private:
    CK_ATTRIBUTE attr_;
    std::shared_ptr<void> ptr_;
};


#endif

