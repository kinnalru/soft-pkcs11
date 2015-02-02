
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <error.h>
#include <termios.h>

#include <iostream>

#include <openssl/bn.h>

#include "tools.h"

int log_fd = 0;


void st_logf(const char* fmt, ...)
{
    if (log_fd == 0) {
        log_fd = ::open("/tmp/soft-token.log", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    }
    
    va_list ap;
    va_start(ap, fmt);
//     vdprintf(STDOUT_FILENO, fmt, ap);
    vdprintf(log_fd, fmt, ap);    
    va_end(ap); 
    
    fsync(log_fd);
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
            st_logf("  * type: <id> size: <%d> value: <%s>\n", attributes[i].ulValueLen, attributes[i].pValue);
            break;
        default:
            st_logf("  * type: <UNKNOWN> size: <%d> type: [0x%08lx]\n", attributes[i].ulValueLen, attributes[i].type);
            break;
        }
    }
}

std::pair<int, std::shared_ptr<unsigned char>> read_bignum(void* ssl_bignum)
{
    BIGNUM *b = reinterpret_cast<BIGNUM*>(ssl_bignum);
    
    int size = BN_num_bytes(b);
    assert(size > 0);

    std::shared_ptr<unsigned char> buff(malloc(size), free);
    assert(buff.get() != NULL);

    int rc = BN_bn2bin(b, buff.get());
    assert(size == rc);
    return std::make_pair(size, buff);
}

std::vector<char> read_all(std::shared_ptr<FILE> file)
{
    std::vector<char> data;

    if (file) {
        std::vector<char> portion(4096);
        while(!::feof(file.get())) {
            portion.resize(4096);
            portion.resize(::fread(portion.data(), 1, portion.size(), file.get()));
            data.insert(data.end(), portion.begin(), portion.end());
        }
    }
    return data;
}

std::shared_ptr< FILE > read_mem(const std::vector< char >& data)
{
    return std::shared_ptr<FILE>(
        ::fmemopen(const_cast<char*>(data.data()), data.size(), "r"),
        ::fclose
    );
}

void set_stdin_echo(bool enable)
{
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if( !enable )
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

std::string read_password()
{
    std::cout << "Input PIN:" << std::endl;
    set_stdin_echo(false);
    std::string pass;
    std::cin >> pass;
    set_stdin_echo(true);
    return pass;
}






