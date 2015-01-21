#ifndef ST_TOOLS_H
#define ST_TOOLS_H

#include "pkcs11/pkcs11u.h"
#include "pkcs11/pkcs11.h"

void st_logf(const char *fmt, ...);

void print_attributes(const CK_ATTRIBUTE *attributes, CK_ULONG num_attributes);


#endif

