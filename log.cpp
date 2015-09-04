
#include <stdarg.h>

#include "tools.h"
#include "log.h"


static logger_t* logger = 0;
static int tab = 0;

logger_t& logger_t::instance()
{
    if (!logger) {
        logger = new logger_t();
    }
    
    return *logger;
}

logger_t& logger_t::operator()(const std::string& msg)
{
    print_tab();
    st_logf(msg.c_str());
    return *this;
}

logger_t& logger_t::operator()(const char* fmt, ...)
{
    print_tab();
    
    va_list ap;
    va_start(ap, fmt);
    st_logf(fmt, ap);    
    va_end(ap); 
    return *this;
}

void logger_t::print_tab()
{
    if (tab > 0) {
        st_logf(std::string(tab * 3, ' ').c_str());
    }
}


logger_t::scopped_t::scopped_t()
{
    ++tab;
}

logger_t::scopped_t::~scopped_t()
{
    --tab;
}



