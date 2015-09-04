#ifndef ST_SOFT_TOKEN_H
#define ST_SOFT_TOKEN_H

#include "types.h"
#include <boost/iterator/filter_iterator.hpp>



typedef std::vector<CK_OBJECT_HANDLE> Handles;
typedef std::function<CK_OBJECT_HANDLE()> handle_iterator_t;

typedef std::map<CK_ATTRIBUTE_TYPE, attribute_t> Attributes;
typedef std::map<CK_OBJECT_HANDLE, Attributes> Objects;

typedef std::function<bool(const Objects::value_type&)> ObjectsPred;
typedef boost::filter_iterator<ObjectsPred, Objects::iterator> ObjectsIterator;


class soft_token_t {
public:
  
    soft_token_t(const std::string& rcfile);
    ~soft_token_t();

    bool ssh_agent() const;
    
    bool ready() const;
    bool logged() const;
    bool login(const std::string& pin);
    void logout();

    std::string full_name() const;
    
    Handles handles() const;
    
    ObjectsIterator begin();
    ObjectsIterator begin(Attributes attrs);
    ObjectsIterator end();
    static CK_OBJECT_HANDLE handle_invalid();    
    
    Attributes attributes(CK_OBJECT_HANDLE id) const;
    bool has_key(CK_OBJECT_HANDLE id) const;
    bool check(CK_OBJECT_HANDLE id, const Attributes& attrs) const;
     
    std::string read(CK_OBJECT_HANDLE id);
    CK_OBJECT_HANDLE write(const std::string& filename, const std::vector<unsigned char>& data, const Attributes& attrs = Attributes());
    
    
    std::vector<unsigned char> sign(CK_OBJECT_HANDLE id, CK_MECHANISM_TYPE type, CK_BYTE_PTR pData, CK_ULONG ulDataLen);
    
    std::vector<unsigned char> create_key(CK_OBJECT_CLASS klass, const Attributes& attrs) const;
    

private:
  
    void check_storage();
    void reset();
  
    struct Pimpl;
    std::auto_ptr<Pimpl> p_;
};



#endif

