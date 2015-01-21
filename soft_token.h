#ifndef ST_SOFT_TOKEN_H
#define ST_SOFT_TOKEN_H

#include <string>
#include <memory>
#include <vector>
#include <map>

#include "pkcs11/pkcs11u.h"
#include "pkcs11/pkcs11.h"

typedef std::vector<CK_OBJECT_HANDLE> ObjectIds;
typedef std::function<CK_OBJECT_HANDLE()> ids_iterator_t;

class soft_token_t {
public:
  
    soft_token_t(const std::string& rcfile);
    ~soft_token_t();
    
    bool logged_in() const;
    
    int open_sessions() const {
      return 0;
    }

    int objects() const;
    ObjectIds object_ids() const;
    
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> attributes(CK_OBJECT_HANDLE id) const;
    
   
    ids_iterator_t ids_iterator() const;
    CK_OBJECT_HANDLE id_invalid() const;

private:
  
    void each_file(const std::string& path, std::function<bool(std::string)> f) const;
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> read_attributes(const std::string& file, const std::string& data, CK_OBJECT_HANDLE& id) const;

    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> data_object_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE& id) const;
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> public_key_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE& id) const;    
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> private_key_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE& id) const;
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> secret_key_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE& id) const;
    
  
    struct Pimpl;
    std::auto_ptr<Pimpl> p_;
};



#endif

