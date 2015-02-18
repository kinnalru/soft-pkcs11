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
    
    bool logged() const;
    bool login(const std::string& pin);
    void logout();

    Handles handles() const;
    
    handle_iterator_t handles_iterator() const;
    handle_iterator_t find_handles_iterator(Attributes attrs) const;
    static CK_OBJECT_HANDLE handle_invalid();    
    
    Attributes attributes(CK_OBJECT_HANDLE id) const;
    bool has_key(CK_OBJECT_HANDLE id) const;
    bool check(CK_OBJECT_HANDLE id, const Attributes& attrs) const;
     
    std::string read(CK_OBJECT_HANDLE id) const;
    CK_OBJECT_HANDLE write(const std::string& filename, const std::string& data) const;
    
    
    std::vector<unsigned char> sign(CK_OBJECT_HANDLE id, CK_MECHANISM_TYPE type, CK_BYTE_PTR pData, CK_ULONG ulDataLen) const;

private:
  
    void check_storage();
    void reset();
  
    struct Pimpl;
    std::auto_ptr<Pimpl> p_;
};



#endif

