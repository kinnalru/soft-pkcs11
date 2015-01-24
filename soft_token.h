#ifndef ST_SOFT_TOKEN_H
#define ST_SOFT_TOKEN_H

#include <string>
#include <memory>
#include <vector>
#include <map>

#include "attribute.h"


typedef std::vector<CK_OBJECT_HANDLE> Handles;
typedef std::function<CK_OBJECT_HANDLE()> handle_iterator_t;

typedef std::map<CK_ATTRIBUTE_TYPE, attribute_t> Attributes;
typedef std::map<CK_OBJECT_HANDLE, Attributes> Objects;

class soft_token_t {
public:
  
    soft_token_t(const std::string& rcfile);
    ~soft_token_t();
    
    bool logged_in() const;

    Handles handles() const;
    
    handle_iterator_t handles_iterator() const;
    handle_iterator_t find_handles_iterator(const Attributes& attrs) const;
    CK_OBJECT_HANDLE handle_invalid() const;    
    
    Attributes attributes(CK_OBJECT_HANDLE id) const;
     
    std::string read(CK_OBJECT_HANDLE id) const;

private:
  
    struct Pimpl;
    std::auto_ptr<Pimpl> p_;
};



#endif

