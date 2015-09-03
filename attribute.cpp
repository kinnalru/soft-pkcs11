
#include <assert.h>
#include <string.h>

#include "attribute.h"

attribute_t::attribute_t(const CK_ATTRIBUTE& other) {
    this->operator=(other);
}    

// attribute_t::attribute_t(CK_ATTRIBUTE_TYPE type, CK_ULONG size) {
//     attr_.type = type;
//     attr_.pValue = NULL_PTR;
//     attr_.ulValueLen = size;
// } 
   
attribute_t::attribute_t(CK_ATTRIBUTE_TYPE type, CK_VOID_PTR value, CK_ULONG size) {
    CK_ATTRIBUTE other;
    other.type = type;
    other.pValue = value;
    other.ulValueLen = size;
    
    this->operator=(other);
}
    
attribute_t::attribute_t(CK_ATTRIBUTE_TYPE type, const std::string& string) {
    CK_ATTRIBUTE other;
    other.type = type;
    other.pValue = const_cast<char*>(string.c_str());
    other.ulValueLen = string.size();
    
    this->operator=(other);
}

attribute_t::attribute_t(CK_ATTRIBUTE_TYPE type, const std::vector<char>& bytes)
{
    CK_ATTRIBUTE other;
    other.type = type;
    other.pValue = const_cast<char*>(bytes.data());
    other.ulValueLen = bytes.size();
    
    this->operator=(other);
}


bool attribute_t::operator==(const attribute_t& other) const
{
    if (other.attr_.type != attr_.type) return false;
    if (other.attr_.ulValueLen != attr_.ulValueLen) return false;
    
    if (other.attr_.pValue == NULL_PTR && attr_.pValue == NULL_PTR) return true;
    
    return memcmp(other.ptr_.get(), ptr_.get(), attr_.ulValueLen) == 0;
}

bool attribute_t::operator!=(const attribute_t& other) const
{
    return !(*this == other);
}

#include "tools.h"

attribute_t& attribute_t::operator=(const CK_ATTRIBUTE& other) {
    if (other.ulValueLen != -1) {
        ptr_.reset(malloc(other.ulValueLen), free);
        if (!ptr_.get()) throw std::bad_alloc();
        memcpy(ptr_.get(), other.pValue, other.ulValueLen);
    }
    
    attr_.type = other.type;
    attr_.pValue = ptr_.get();
    attr_.ulValueLen = other.ulValueLen;
    return *this;
}
    
void attribute_t::apply(CK_ATTRIBUTE& dst) const {
    assert(dst.type == attr_.type);
    
    if (dst.pValue != NULL_PTR && attr_.pValue != NULL_PTR && dst.ulValueLen >= attr_.ulValueLen)
    {
        memcpy(dst.pValue, attr_.pValue, attr_.ulValueLen);
    }
    
    dst.ulValueLen = attr_.ulValueLen;
}
    