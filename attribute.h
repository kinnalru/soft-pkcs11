#ifndef ST_ATTRIBUTE_H
#define ST_ATTRIBUTE_H

#include <memory>
#include <vector>

#include "pkcs11/pkcs11u.h"
#include "pkcs11/pkcs11.h"

struct attribute_t {

    attribute_t() : attr_({0,0,0}) {}
    attribute_t(const CK_ATTRIBUTE& other);
    
    attribute_t(CK_ATTRIBUTE_TYPE type, CK_VOID_PTR value, CK_ULONG size);
    
    attribute_t(CK_ATTRIBUTE_TYPE type, const std::string& string);
    attribute_t(CK_ATTRIBUTE_TYPE type, const std::vector<char>& bytes);
    
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
    
    template<typename T>
    inline T value() const {
        return reinterpret_cast<T>(attr_.pValue);
    }
    
    template<typename T>
    inline T to_value() const {
        return (attr_.pValue) 
            ? *(reinterpret_cast<T*>(attr_.pValue))
            : 0;
    }
    
    inline CK_OBJECT_HANDLE to_handle() const {
        return to_value<CK_OBJECT_HANDLE>();
    }
    
    inline CK_ULONG to_id() const {
        return to_value<CK_ULONG>();
    }
    
    inline const std::string to_object_id() const {
        return to_string();
    }
    
    inline const std::string to_string() const {
        return (attr_.pValue) 
            ? std::string(reinterpret_cast<char*>(attr_.pValue), attr_.ulValueLen)
            : std::string("");
    }
    
    inline const std::vector<unsigned char> to_bytes() const {
        return std::vector<unsigned char>(reinterpret_cast<unsigned char*>(attr_.pValue), reinterpret_cast<unsigned char*>(attr_.pValue) + attr_.ulValueLen);
    }
    
    inline bool to_bool() const {
        if (attr_.ulValueLen != sizeof(CK_BBOOL)) {
            throw std::runtime_error("can't cast to CK_BBOOL: invalid value length");
        }
        return attr_.pValue && *(reinterpret_cast<CK_BBOOL*>(attr_.pValue)) == CK_TRUE;
    }
    
    inline CK_OBJECT_CLASS to_class() const {
        if (attr_.ulValueLen != sizeof(CK_OBJECT_CLASS)) {
            throw std::runtime_error("can't cast to CK_OBJECT_CLASS: invalid value length");
        }
        return to_value<CK_OBJECT_CLASS>();
    }
    
private:
    CK_ATTRIBUTE attr_;
    std::shared_ptr<void> ptr_;
};


#endif

