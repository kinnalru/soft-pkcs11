
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <iostream>
#include <fstream>
#include <functional>

#include <boost/bind.hpp>
#include <boost/iterator/filter_iterator.hpp>
#include <boost/iterator/transform_iterator.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/filesystem.hpp>

#include "tools.h"
#include "soft_token.h"


namespace fs = boost::filesystem;


Attributes data_object_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE id);
Attributes public_key_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE id);    
Attributes private_key_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE id);
Attributes secret_key_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE id);

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

struct to_attributes : std::unary_function<const fs::directory_entry&, Objects::value_type> {
    Objects::value_type operator() (const fs::directory_entry& d) const {
        const auto id = to_object_id()(d);
        std::ifstream t(d.path().string());
        const std::string data((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
        
        Attributes attrs;
        
        if (is_private_key()(data)) {
            attrs = private_key_attrs(d.path().filename().string(), data, id);
        }
        else if (is_public_key()(data)) {
            attrs = public_key_attrs(d.path().filename().string(), data, id);
        } 
        else {
            attrs = data_object_attrs(d.path().filename().string(), data, id);    
        }
        
        return std::make_pair(id, attrs);
    }
};


typedef boost::filter_iterator<std::function<bool(const fs::directory_entry&)>, fs::directory_iterator> files_iterator;
typedef boost::transform_iterator<to_object_id, files_iterator> object_ids_iterator;


struct soft_token_t::Pimpl {
  
    Pimpl() {
      config.put("path", "default");
    }
    
    files_iterator files_begin() const {
        if (fs::exists(path) && fs::is_directory(path)) {
            return files_iterator(is_object(), fs::directory_iterator(path));
        }    
        
        return files_end();
    };
    
    files_iterator files_end() const {
        return files_iterator(fs::directory_iterator());
    }
    
    
    
    Objects::const_iterator find(std::function<bool(const Objects::value_type&)> pred) const {
        return std::find_if(objects.begin(), objects.end(), pred);
    }
    
    template<typename Pred>
    boost::filter_iterator<Pred, Objects::const_iterator> filter_iterator(Pred pred) const {
        return boost::filter_iterator<Pred, Objects::const_iterator>(pred, objects.begin(), objects.end());
    }
    
    template<typename Pred>
    boost::filter_iterator<Pred, Objects::const_iterator> filter_end(Pred pred) const {
        return boost::filter_iterator<Pred, Objects::const_iterator>(pred, objects.end(), objects.end());
    }

    template<typename Trans, typename It = Objects::const_iterator>
    boost::transform_iterator<Trans, It> trans_iterator(Trans trans, It* b = NULL) const {
        auto tmp = objects.begin();
        if (b == NULL) {
            b = reinterpret_cast<It*>(&tmp); //HACK
        }
        
        return boost::transform_iterator<Trans, It>(*b, trans);
    }
    
    template<typename Trans, typename It = Objects::const_iterator>
    boost::transform_iterator<Trans, It> trans_end(Trans trans, It* e = NULL) const {
        auto tmp = objects.end();
        if (e == NULL) {
            e = reinterpret_cast<It*>(&tmp); //HACK
        }
        
        return boost::transform_iterator<Trans, It>(*e, trans);
    }

    std::vector<int> vi;
  
    boost::property_tree::ptree config;
    std::string path;
    Objects objects;
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
    
    const auto end = p_->files_end();
    const to_attributes convert;
    for(auto it = p_->files_begin(); it != end; ++it ) {
        st_logf("Finded obejcts:\n");
        p_->objects.insert(convert(*it));
    }
    
}

soft_token_t::~soft_token_t()
{
    std::cerr << "DESTRUCTOR 1" << std::endl;
    p_.reset();
    std::cerr << "DESTRUCTOR 2" << std::endl;
}

bool soft_token_t::logged_in() const
{
    return false;

}

Handles soft_token_t::handles() const
{
    return Handles(
        p_->trans_iterator(boost::bind(&Objects::value_type::first,_1)),
        p_->trans_end(boost::bind(&Objects::value_type::first,_1))
    );
}

handle_iterator_t soft_token_t::handles_iterator() const
{
    auto it = p_->trans_iterator(boost::bind(&Objects::value_type::first,_1));
    auto end = p_->trans_end(boost::bind(&Objects::value_type::first,_1));
    
    return handle_iterator_t([it, end] () mutable {
        if (it != end) {
            return *(it++);
        }
        else {
            return static_cast<CK_OBJECT_HANDLE>(-1);  
        }
    });
}

struct find_by_attrs : std::unary_function<const Objects::value_type, bool> {
    find_by_attrs(const Attributes& a) : attrs(a) {}
    
    bool operator()(const Objects::value_type object_pair) const {
        for (auto it = attrs.begin(); it != attrs.end(); ++it) {
            const Attributes& object_attrs = object_pair.second;
            
            auto fnd = object_attrs.find(it->first);
            if (fnd != object_attrs.end()) {
                if (fnd->second != it->second) {
                    return false;
                }
            }
            else {
                return false;
            }
        }
        
        return true;
    };
    
private:
    const Attributes attrs;
};

handle_iterator_t soft_token_t::find_handles_iterator(const Attributes& attrs) const
{
    auto finded_it = p_->filter_iterator(find_by_attrs(attrs));
    auto finded_end = p_->filter_end(find_by_attrs(attrs));
    
    auto it = p_->trans_iterator(boost::bind(&Objects::value_type::first,_1), &finded_it);
    auto end = p_->trans_end(boost::bind(&Objects::value_type::first,_1), &finded_end);
    
    return handle_iterator_t([it, end] () mutable {
        if (it != end) {
            return *(it++);
        }
        else {
            return static_cast<CK_OBJECT_HANDLE>(-1);  
        }
    });
}

CK_OBJECT_HANDLE soft_token_t::handle_invalid() const
{
    return static_cast<CK_OBJECT_HANDLE>(-1);  
}


Attributes soft_token_t::attributes(CK_OBJECT_HANDLE id) const
{
    auto it = p_->objects.find(id);
    
    if (it != p_->objects.end()) {
        return it->second;
    }
    
    return Attributes();
}

std::string soft_token_t::read(CK_OBJECT_HANDLE id) const
{
    to_object_id conv;
    auto it = std::find_if(p_->files_begin(), p_->files_end(), [&conv, id](const fs::directory_entry& d) {
        return conv(d) == id;
    });
    
    if (it != p_->files_end()) {
        std::ifstream t(it->path().string());
        return std::string((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
    }
    
    return std::string();
}


const CK_BBOOL bool_true = CK_TRUE;
const CK_BBOOL bool_false = CK_FALSE;

Attributes data_object_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE id)
{
    const CK_OBJECT_CLASS klass = CKO_DATA;
    const CK_FLAGS flags = 0;
    
    Attributes attributes = {
        create_object(CKA_CLASS,     klass),

//         std::make_pair(CKA_VALUE, attribute_t(CKA_VALUE, data.size())), // SPECIAL CASE FOR VALUE
        
        //Common Storage Object Attributes
        create_object(CKA_TOKEN,     bool_true),
        create_object(CKA_PRIVATE,   bool_true),
        create_object(CKA_MODIFIABLE,bool_false),
        create_object(CKA_LABEL,     file),
        
    };

    return attributes;
}

Attributes public_key_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE id)
{
    const CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;
    const CK_MECHANISM_TYPE mech_type = CKM_RSA_X_509;

    //ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-20/pkcs-11v2-20.pdf
    Attributes attributes = {
        create_object(CKA_CLASS,     klass),
        
//         std::make_pair(CKA_VALUE, attribute_t(CKA_VALUE, data.size())), // SPECIAL CASE FOR VALUE
        
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

Attributes private_key_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE id)
{
    const CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
    const CK_MECHANISM_TYPE mech_type = CKM_RSA_X_509;
    
    Attributes attributes = {
        create_object(CKA_CLASS,     klass),
        
//         std::make_pair(CKA_VALUE, attribute_t(CKA_VALUE, data.size())), // SPECIAL CASE FOR VALUE
        
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

Attributes secret_key_attrs(const std::string& file, const std::string& data, CK_OBJECT_HANDLE id)
{
    const CK_OBJECT_CLASS klass = CKO_SECRET_KEY;
    const CK_MECHANISM_TYPE mech_type = CKM_RSA_X_509;
    
    //ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-20/pkcs-11v2-20.pdf
    Attributes attributes = {
        create_object(CKA_CLASS,     klass),
        
//         std::make_pair(CKA_VALUE, attribute_t(CKA_VALUE, data.size())), // SPECIAL CASE FOR VALUE
        
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









