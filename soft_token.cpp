
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <iostream>
#include <fstream>
#include <functional>

#include <boost/iterator/filter_iterator.hpp>
#include <boost/iterator/transform_iterator.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/filesystem.hpp>

#include "tools.h"
#include "soft_token.h"


namespace fs = boost::filesystem;

struct is_object : std::unary_function<const fs::directory_entry&, bool> {
    bool operator() (const fs::directory_entry& d) const {
        return fs::is_regular_file(d.status());
    }
};

struct to_object_id : std::unary_function<const fs::directory_entry&, CK_OBJECT_HANDLE> {
    CK_OBJECT_HANDLE operator() (const fs::directory_entry& d) const {
        return static_cast<CK_OBJECT_HANDLE>(hash(d.path().filename().c_str()));
    }
private:
    std::hash<std::string> hash;
};

struct is_private_key : std::unary_function<const fs::directory_entry&, bool> {
    bool operator() (const fs::directory_entry& d) {
      std::ifstream infile(d.path().string());
      std::string first_line;
      std::getline(infile, first_line, '\n');
      return first_line == "-----BEGIN RSA PRIVATE KEY-----";        
    }
    
    bool operator() (const std::string& data) {
      std::stringstream infile(data);
      std::string first_line;
      std::getline(infile, first_line, '\n');
      return first_line == "-----BEGIN RSA PRIVATE KEY-----";        
    }
};

struct is_public_key : std::unary_function<const fs::directory_entry&, bool> {
    bool operator() (const fs::directory_entry& d) {
      std::ifstream infile(d.path().string());
      std::string first_line;
      std::getline(infile, first_line, '\n');
      return (first_line.find("ssh-rsa") == 0)
        || first_line == "-----BEGIN PUBLIC KEY-----"
        || first_line == "-----BEGIN RSA PUBLIC KEY-----";        
    }
    
    bool operator() (const std::string& data) {
      std::stringstream infile(data);
      std::string first_line;
      std::getline(infile, first_line, '\n');
      return (first_line.find("ssh-rsa") == 0)
        ||first_line == "-----BEGIN PUBLIC KEY-----"
        || first_line == "-----BEGIN RSA PUBLIC KEY-----";        
    }
};

typedef boost::filter_iterator<std::function<bool(const fs::directory_entry&)>, fs::directory_iterator> objects_iterator;
typedef boost::transform_iterator<to_object_id, objects_iterator> object_ids_iterator;


struct soft_token_t::Pimpl {
  
    Pimpl() {
      config.put("path", "default");
    }
    
    objects_iterator objects_begin() const {
        if (fs::exists(path) && fs::is_directory(path)) {
            return objects_iterator(is_object(), fs::directory_iterator(path));
        }    
        
        return objects_end();
    };
    
    objects_iterator objects_end() const {
        return objects_iterator(fs::directory_iterator());
    }
    
    objects_iterator find(std::function<bool(const fs::directory_entry&)> pred) const {
        return std::find_if(objects_begin(), objects_end(), pred);
    }
    
    template<typename Pred>
    boost::filter_iterator<Pred, objects_iterator> filter_iterator(Pred pred) const {
        return boost::filter_iterator<Pred, objects_iterator>(pred, objects_begin(), objects_end());
    }
    
    template<typename Pred>
    boost::filter_iterator<Pred, objects_iterator> filter_end(Pred pred) const {
        return boost::filter_iterator<Pred, objects_iterator>(pred, objects_end(), objects_end());
    }
  
    boost::property_tree::ptree config;
    std::string path;
};

int read_password (char *buf, int size, int rwflag, void *userdata) {
    std::string p;
    std::cin >> p;
    std::copy_n(p.begin(), std::min(size, static_cast<int>(p.size())), buf);
    return p.size();
}

bool check_file_is_private_key(const std::string& file) {
    std::ifstream infile(file);
    std::string first_line;
    std::getline(infile, first_line, '\n');
    return first_line == "-----BEGIN RSA PRIVATE KEY-----";
}

soft_token_t::soft_token_t(const std::string& rcfile)
    : p_(new Pimpl())
{
   
    try {
      boost::property_tree::ini_parser::read_ini(rcfile, p_->config);
    }
    catch (...) {}
    
    p_->path = p_->config.get<std::string>("path");
    
    st_logf("Config file: %s\n", rcfile.c_str());
    st_logf("Path : %s\n", p_->path.c_str());
    st_logf("Finded obejcts:\n");
    for(auto it = p_->objects_begin(); it != p_->objects_end(); ++it ) {
        st_logf(" * %s\n", it->path().filename().c_str());
    }
    

//     each_file(p_->config.get<std::string>("path"), [](std::string s) {
//       
//         std::cerr << s << " Is key: " << check_file_is_private_key(s) << std::endl;;
//         return;
//       
//         FILE* f = fopen(s.c_str(), "r");
//         
//         if (f == NULL) {
//             std::cerr << "Error open file:" << s << std::endl;
//         }
//         
//         EVP_PKEY *key = PEM_read_PrivateKey(f, NULL, read_password, NULL);
//         
//         if (key == NULL) {
//             std::cerr << "failed to read key: " << s.c_str() << " Err:"<< ERR_error_string(ERR_get_error(), NULL);
//         }
//     });
}

soft_token_t::~soft_token_t()
{
    std::cerr << "DESTRUCTOR 1" << std::endl;
//     p_.reset();
    std::cerr << "DESTRUCTOR 2" << std::endl;
}

int soft_token_t::objects() const
{
    int result = 0;
    each_file(p_->config.get<std::string>("path"), [&result] (std::string s) {
        if (check_file_is_private_key(s)) ++result;
              
        return false;
    });
    return result;
}

ObjectIds soft_token_t::object_ids() const
{
    return ObjectIds(object_ids_iterator(p_->objects_begin()), object_ids_iterator(p_->objects_end()));
}

std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> soft_token_t::attributes(CK_OBJECT_HANDLE id) const
{
    auto it = p_->find([id ](const fs::directory_entry& d) {
        return to_object_id()(d) == id;
    });
  
    if (it != p_->objects_end()) {
        std::ifstream t(it->path().string());
        std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
        return read_attributes(it->path().filename().string(), str, id);
    }
    
    st_logf("Object with id: %lu not found", id);
    
    return std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE>();
}

 
template <typename T>
inline std::pair<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> create_object(CK_ATTRIBUTE_TYPE type, const T& object) {
    CK_ATTRIBUTE attr = {type, malloc(sizeof(T)), sizeof(T)}; 
    if (!attr.pValue) throw std::bad_alloc();
    memcpy(attr.pValue, &object, sizeof(T));
    return std::make_pair(type, attr);
}

inline std::pair<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> create_object(CK_ATTRIBUTE_TYPE type, const std::string& string) {
    CK_ATTRIBUTE attr = {type, malloc(string.size() + 1), string.size() + 1}; 
    if (!attr.pValue) throw std::bad_alloc();
    memcpy(attr.pValue, string.c_str(), string.size() + 1);
    return std::make_pair(type, attr);
}

std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> soft_token_t::read_attributes(const std::string& file, const std::string& data, CK_OBJECT_HANDLE& id) const
{
    if (is_private_key()(data)) {
        return private_key_attrs(file, data, id);
    }
    else if (is_public_key()(data)) {
        return public_key_attrs(file, data, id);
    }
    
    return data_object_attrs(file, data, id);
}

const CK_BBOOL bool_true = CK_TRUE;
const CK_BBOOL bool_false = CK_FALSE;

std::map< CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE > soft_token_t::data_object_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE& id) const
{
    const CK_OBJECT_CLASS klass = CKO_DATA;
    const CK_FLAGS flags = 0;
    
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> attributes = {
        create_object(CKA_CLASS,     klass),
        
        //Common Storage Object Attributes
        create_object(CKA_TOKEN,     bool_true),
        create_object(CKA_PRIVATE,   bool_true),
        create_object(CKA_MODIFIABLE,bool_false),
        create_object(CKA_LABEL,     file),
    };

    return attributes;
}

std::map< CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE > soft_token_t::public_key_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE& id) const
{
    const CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;
    const CK_MECHANISM_TYPE mech_type = CKM_RSA_X_509;

    //ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-20/pkcs-11v2-20.pdf
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> attributes = {
        create_object(CKA_CLASS,     klass),
        
        //Common Storage Object Attributes
        create_object(CKA_TOKEN,     bool_true),
        create_object(CKA_PRIVATE,   bool_false),
        create_object(CKA_MODIFIABLE,bool_false),
        create_object(CKA_LABEL,     file),
        
        //Common Key Attributes
        //create_object(CKA_KEY_TYPE,        id),
        create_object(CKA_ID,        id),
        //create_object(CKA_START_DATE,        id),
        //create_object(CKA_END_DATE,        id),
        create_object(CKA_DERIVE,    bool_false),
        create_object(CKA_LOCAL,     bool_false),
        create_object(CKA_KEY_GEN_MECHANISM, mech_type),
        
        //Common Public Key Attributes
        //create_object(CKA_SUBJECT,   bool_true),
        create_object(CKA_ENCRYPT,   bool_true),
        create_object(CKA_VERIFY,    bool_true),
        //create_object(CKA_VERIFY_RECOVER,   bool_false),
        //create_object(CKA_TRUSTED10,   bool_true),
        //create_object(CKA_WRAP_TEMPLATE ,   bool_true),
        
        /////////////

    };

    return attributes;    
}

std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> soft_token_t::private_key_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE& id) const
{
    const CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
    const CK_MECHANISM_TYPE mech_type = CKM_RSA_X_509;
    
    //ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-20/pkcs-11v2-20.pdf
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> attributes = {
        create_object(CKA_CLASS,     klass),
        
        //Common Storage Object Attributes
        create_object(CKA_TOKEN,     bool_true),
        create_object(CKA_PRIVATE,   bool_true),
        create_object(CKA_MODIFIABLE,bool_false),
        create_object(CKA_LABEL,     file),
        
        //Common Key Attributes
        //create_object(CKA_KEY_TYPE,        id),
        create_object(CKA_ID,        id),
        //create_object(CKA_START_DATE,        id),
        //create_object(CKA_END_DATE,        id),
        create_object(CKA_DERIVE,    bool_false),
        create_object(CKA_LOCAL,     bool_false),
        create_object(CKA_KEY_GEN_MECHANISM, mech_type),
        
        //Common Private Key Attributes
        //create_object(CKA_SUBJECT,   bool_true),
        create_object(CKA_SENSITIVE,      bool_true), //bool_false
        create_object(CKA_DECRYPT,   bool_true),
        create_object(CKA_SIGN,      bool_true),
        create_object(CKA_SIGN_RECOVER, bool_false),
        create_object(CKA_UNWRAP,    bool_true),
        create_object(CKA_EXTRACTABLE, bool_true),
        //create_object(CKA_ALWAYS_SENSITIVE, bool_true),
        create_object(CKA_NEVER_EXTRACTABLE, bool_false),
        //create_object(CKA_WRAP_WITH_TRUSTED1, bool_false),
        //create_object(CKA_UNWRAP_TEMPLATE, bool_false),
        create_object(CKA_ALWAYS_AUTHENTICATE, bool_true),
        
        /////////////

    };

    return attributes;
}

std::map< CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE > soft_token_t::secret_key_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE& id) const
{
    const CK_OBJECT_CLASS klass = CKO_SECRET_KEY;
    const CK_MECHANISM_TYPE mech_type = CKM_RSA_X_509;
    
    //ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-20/pkcs-11v2-20.pdf
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> attributes = {
        create_object(CKA_CLASS,     klass),
        
        //Common Storage Object Attributes
        create_object(CKA_TOKEN,     bool_true),
        create_object(CKA_PRIVATE,   bool_true),
        create_object(CKA_MODIFIABLE,bool_false),
        create_object(CKA_LABEL,     file),
        
        //Common Key Attributes
        //create_object(CKA_KEY_TYPE,        id),
        create_object(CKA_ID,        id),
        //create_object(CKA_START_DATE,        id),
        //create_object(CKA_END_DATE,        id),
        create_object(CKA_DERIVE,    bool_false),
        create_object(CKA_LOCAL,     bool_false),
        create_object(CKA_KEY_GEN_MECHANISM, mech_type),
        
        //Common Secret Key Attributes
        create_object(CKA_SENSITIVE,      bool_true), //bool_false
        create_object(CKA_ENCRYPT,   bool_true),
        create_object(CKA_DECRYPT,   bool_true),
        create_object(CKA_SIGN,      bool_true),
        create_object(CKA_VERIFY,    bool_false),
        create_object(CKA_WRAP,      bool_false),
        create_object(CKA_UNWRAP,    bool_false),
        create_object(CKA_EXTRACTABLE, bool_true),
        //create_object(CKA_ALWAYS_SENSITIVE, bool_true),
        create_object(CKA_NEVER_EXTRACTABLE, bool_false),
        //create_object(CKA_CHECK_VALUE, bool_false),
        //create_object(CKA_WRAP_WITH_TRUSTED, bool_false),
        //create_object(CKA_TRUSTED, bool_false),
        //create_object(CKA_WRAP_TEMPLATE, bool_false),
        //create_object(CKA_UNWRAP_TEMPLATE, bool_false),
        create_object(CKA_ALWAYS_AUTHENTICATE, bool_true),
        
        /////////////

    };

    return attributes;
}







 


bool soft_token_t::logged_in() const
{
    return false;
}

void soft_token_t::each_file(const std::string& path, std::function<bool(std::string)> f) const
{
    for(auto it = p_->objects_begin(); it != p_->objects_end(); ++it) {
        if (f(it->path().string())) return;
    }
}


ids_iterator_t soft_token_t::ids_iterator() const
{
    auto it = object_ids_iterator(p_->objects_begin());
    auto end = object_ids_iterator(p_->objects_end());
    
    return ids_iterator_t([it, end] () mutable {
        if (it != end) {
            return *(it++);
        }
        else {
            return static_cast<CK_OBJECT_HANDLE>(-1);  
        }
    });
}

CK_OBJECT_HANDLE soft_token_t::id_invalid() const
{
    return static_cast<CK_OBJECT_HANDLE>(-1);  
}





