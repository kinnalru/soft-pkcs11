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

std::vector<char> read_all(std::shared_ptr<FILE> file);

std::shared_ptr<FILE> read_mem(const std::vector<char>& data);

std::shared_ptr<FILE> write_mem(char **buf, size_t *size);


std::string read_password();

std::vector<char> piped(const std::string& cmd, const std::vector<char>& input = std::vector<char>());

int start(const std::string& cmd, const std::vector<char>& input = std::vector<char>());


#endif

