#ifndef ST_SOFT_TOKEN_H
#define ST_SOFT_TOKEN_H

#include <string>
#include <memory>
#include <vector>
#include <map>

#include "pkcs11/pkcs11u.h"
#include "pkcs11/pkcs11.h"

class soft_token_t {
public:
  
    soft_token_t(const std::string& rcfile);
    ~soft_token_t();
    
    bool logged_in() const;
    
    int open_sessions() const {
      return 0;
    }

    int objects() const;
    std::vector<std::size_t> object_ids() const;
    
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> attributes(std::size_t id) const;

private:
    void each_file(const std::string& path, std::function<bool(std::string)> f) const;
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> read_attributes(const std::string& file, const std::string& data, std::size_t& id) const;
  
    struct Pimpl;
    std::auto_ptr<Pimpl> p_;
};



#endif

