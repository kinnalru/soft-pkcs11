
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tools.h"

void st_logf(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
     vdprintf(STDOUT_FILENO, fmt, ap);
    va_end(ap); 
}
 
void print_attributes(const CK_ATTRIBUTE *attributes, CK_ULONG num_attributes)
{
    CK_ULONG i;

    st_logf("Print attributes: %lu\n", num_attributes);

    for (i = 0; i < num_attributes; i++) {
        switch (attributes[i].type) {
        case CKA_TOKEN: {
            if (attributes[i].ulValueLen != sizeof(CK_BBOOL)) {
                st_logf("  * token attribute(%d) wrong length size: <%d>\n", CKA_TOKEN, attributes[i].ulValueLen);
                break;
            }
            st_logf("  * type: <token> size: <%d> value: <%s>\n", attributes[i].ulValueLen, *((CK_BBOOL*)attributes[i].pValue) ? "TRUE" : "FALSE");
            break;
        }
        case CKA_CLASS: {
            
            if (attributes[i].ulValueLen != sizeof(CK_ULONG)) {
                st_logf("  * token attribute(%d) wrong length size: <%d>\n", CKA_CLASS, attributes[i].ulValueLen);
                break;
            }
            CK_OBJECT_CLASS klass = *((CK_OBJECT_CLASS*)attributes[i].pValue);
            switch (klass) {
            case CKO_CERTIFICATE:
                st_logf("  * type: <class> size: <%d> value: <%s>\n", attributes[i].ulValueLen, "certificate");
                break;
            case CKO_PUBLIC_KEY:
                st_logf("  * type: <class> size: <%d> value: <%s>\n", attributes[i].ulValueLen, "public key");
                break;
            case CKO_PRIVATE_KEY:
                st_logf("  * type: <class> size: <%d> value: <%s>\n", attributes[i].ulValueLen, "private key");
                break;
            case CKO_SECRET_KEY:
                st_logf("  * type: <class> size: <%d> value: <%s>\n", attributes[i].ulValueLen, "secret key");
                break;
            case CKO_DOMAIN_PARAMETERS:
                st_logf("  * type: <class> size: <%d> value: <%s>\n", attributes[i].ulValueLen, "domain parameters");
                break;
            default:
                st_logf("  * type: <class> size: <%d> value: [class 0x%08lx]\n", attributes[i].ulValueLen, klass);
                break;
            }
            break;
        }
        case CKA_PRIVATE:
            st_logf("  * type: <private> size: <%d>\n", attributes[i].ulValueLen);
            break;
        case CKA_LABEL:
            st_logf("  * type: <label> size: <%d> value: <%s>\n", attributes[i].ulValueLen, attributes[i].pValue);
            break;
        case CKA_APPLICATION:
            st_logf("  * type: <application> size: <%d>\n", attributes[i].ulValueLen);
            break;
        case CKA_VALUE:
            st_logf("  * type: <value> size: <%d>\n", attributes[i].ulValueLen);
            break;
        case CKA_ID:
            st_logf("  * type: <id> size: <%d>\n", attributes[i].ulValueLen);
            break;
        default:
            st_logf("  * type: <UNKNOWN> size: <%d> type: [0x%08lx]\n", attributes[i].ulValueLen, attributes[i].type);
            break;
        }
    }
}