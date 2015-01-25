#ifndef ST_TOOLS_H
#define ST_TOOLS_H

#include "pkcs11/pkcs11u.h"
#include "pkcs11/pkcs11.h"

#include "attribute.h"

void st_logf(const char *fmt, ...);

void print_attributes(const CK_ATTRIBUTE *attributes, CK_ULONG num_attributes);

std::pair<int, std::shared_ptr<unsigned char>> read_bignum(void* ssl_bignum);

template <typename T>
inline std::pair<CK_ATTRIBUTE_TYPE, attribute_t> create_object(CK_ATTRIBUTE_TYPE type, const T& object) {
    return std::make_pair(type, attribute_t(type, object)); 
}

#endif

