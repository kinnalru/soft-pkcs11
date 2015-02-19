#ifndef ST_EXCEPTIONS_H
#define ST_EXCEPTIONS_H

#include <stdexcept>

#include "pkcs11/pkcs11t.h"

struct pkcs11_exception_t : std::runtime_error {
    explicit pkcs11_exception_t(CK_RV r, const std::string& msg)
      : std::runtime_error(msg)
      , rv(rv)
    {}
  
    CK_RV rv;
};

struct system_exception_t : std::runtime_error {
    explicit system_exception_t(const std::string& msg)
      : std::runtime_error(msg)
    {}
};
#endif

