
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

struct descriptor_t;
typedef std::shared_ptr<descriptor_t> descriptor_p;

Attributes data_object_attrs(descriptor_p desc);
Attributes public_key_attrs(descriptor_p desc);    
Attributes private_key_attrs(descriptor_p desc);
Attributes secret_key_attrs(descriptor_p desc);

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

struct descriptor_t {
    descriptor_t(const fs::directory_entry& d)
        : fullname(d.path().string())
        , filename(d.path().filename().string())
    {
        std::ifstream stream1(d.path().string());
        std::getline(stream1, first_line, '\n');
        stream1.seekg (0, stream1.beg);
        
        std::ifstream stream(d.path().string());
        
        data = std::vector<char>((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        id = to_object_id()(d);
        file = ::fmemopen(data.data(), data.size(), "r");
    }
    
    ~descriptor_t() {
        ::fclose(file);
    }
    
    const std::string fullname;
    const std::string filename;
    std::vector<char> data;
    std::string first_line;
    CK_OBJECT_HANDLE id;
    FILE *file;
};


struct is_private_key : std::unary_function<descriptor_p, bool> {
    bool operator() (descriptor_p desc) {
        return desc->first_line == "-----BEGIN RSA PRIVATE KEY-----";        
    }
};

struct is_public_key : std::unary_function<descriptor_p, bool> {
    bool operator() (descriptor_p desc) {
      return (desc->first_line.find("ssh-rsa") == 0)
        || desc->first_line == "-----BEGIN PUBLIC KEY-----"
        || desc->first_line == "-----BEGIN RSA PUBLIC KEY-----";        
    }
};

struct to_attributes : std::unary_function<const fs::directory_entry&, Objects::value_type> {
    Objects::value_type operator() (const fs::directory_entry& d) const {
        
        descriptor_p desc(new descriptor_t(d));
        
        Attributes attrs;

        if (is_private_key()(desc)) {
            attrs = private_key_attrs(desc);
        }
        else if (is_public_key()(desc)) {
            attrs = public_key_attrs(desc);
        } 
        else {
            attrs = data_object_attrs(desc);    
        }
        
        return std::make_pair(desc->id, attrs);
    }
};

struct find_by_attrs : std::unary_function<const Objects::value_type, bool> {
    find_by_attrs(const Attributes& a) : attrs(a) {}
    
    bool operator()(const Objects::value_type object_pair) const {
        
        st_logf("SEARCH FOR ID: %lu\n", object_pair.first);        
        
        for (auto it = attrs.begin(); it != attrs.end(); ++it) {
            const Attributes& object_attrs = object_pair.second;
            
            st_logf("compare attr type:: %d\n", it->first);        
            
            auto fnd = object_attrs.find(it->first);
            if (fnd != object_attrs.end()) {
                if (fnd->second != it->second) {
                    if (it->first == CKA_ID) {
                        st_logf("TYPE: %d\n",it->first);
                        
                        st_logf("second1: %d\n", it->second->type);
                        st_logf("second1: %d\n", it->second->ulValueLen);
                        st_logf("second1: %s\n", (char*)it->second->pValue);
                        
                        st_logf("second2: %d\n", fnd->second->type);
                        st_logf("second2: %d\n", fnd->second->ulValueLen);
                        st_logf("second2: %s\n", (char*)fnd->second->pValue);
                    
                        
                        st_logf("COMPARE:  %d\n", memcmp(it->second->pValue, fnd->second->pValue, fnd->second->ulValueLen));
                    }
                    st_logf("attr type %d NOT EQUAL\n", it->first);
                    return false;
                }
            }
            else {
                st_logf("attr type %d NOT FOUND\n", it->first);
                return false;
            }
        }
        
        st_logf("object MATCH\n");
        return true;
    };
    
private:
    const Attributes attrs;
};

typedef boost::filter_iterator<std::function<bool(const fs::directory_entry&)>, fs::directory_iterator> files_iterator;
typedef boost::transform_iterator<to_object_id, files_iterator> object_ids_iterator;

typedef std::function<bool(const Objects::value_type&)> ObjectsPred;

struct soft_token_t::Pimpl {
  
    Pimpl() {
      config.put("path", "default");
    }
    
    /// Iterate over all files in path
    files_iterator files_begin() const {
        if (fs::exists(path) && fs::is_directory(path)) {
            return files_iterator(is_object(), fs::directory_iterator(path));
        }    
        
        return files_end();
    };
    
    /// end-iterator
    files_iterator files_end() const {
        return files_iterator(fs::directory_iterator());
    }
    
    
    /// Find in objects by predicate
    Objects::const_iterator find(std::function<bool(const Attributes&)> pred) const {
        return std::find_if(objects.begin(), objects.end(), [&pred] (const Objects::value_type& v) {
            return pred(v.second);
        });
    }
    
    /// Find in objects by predicate
    Objects::iterator find(std::function<bool(const Attributes&)> pred) {
        return std::find_if(objects.begin(), objects.end(), [&pred] (const Objects::value_type& v) {
            return pred(v.second);
        });
    }
    
    
    /// Filter objects by predicate
    boost::filter_iterator<ObjectsPred, Objects::const_iterator> filter_iterator(ObjectsPred pred) const {
        return boost::filter_iterator<ObjectsPred, Objects::const_iterator>(pred, objects.begin(), objects.end());
    }
    
    /// Filter objects by predicate
    boost::filter_iterator<ObjectsPred, Objects::iterator> filter_iterator(ObjectsPred pred) {
        return boost::filter_iterator<ObjectsPred, Objects::iterator>(pred, objects.begin(), objects.end());
    }

    /// Filter objects by attributes
    boost::filter_iterator<ObjectsPred, Objects::const_iterator> filter_iterator(const Attributes& attrs) const {
        return boost::filter_iterator<ObjectsPred, Objects::const_iterator>(find_by_attrs(attrs), objects.begin(), objects.end());
    }
    
    /// Filter objects by attributes
    boost::filter_iterator<ObjectsPred, Objects::iterator> filter_iterator(const Attributes& attrs) {
        return boost::filter_iterator<ObjectsPred, Objects::iterator>(find_by_attrs(attrs), objects.begin(), objects.end());
    }

    /// Filter end iterator
    boost::filter_iterator<ObjectsPred, Objects::const_iterator> filter_end() const {
        return boost::filter_iterator<ObjectsPred, Objects::const_iterator>(ObjectsPred(), objects.end(), objects.end());
    }
    
    /// Filter end iterator
    boost::filter_iterator<ObjectsPred, Objects::iterator> filter_end() {
        return boost::filter_iterator<ObjectsPred, Objects::iterator>(ObjectsPred(), objects.end(), objects.end());
    }
    


    
    /// Iterate over transformed(through trans-function) collection
    template<typename Trans, typename It = Objects::const_iterator>
    boost::transform_iterator<Trans, It> trans_iterator(Trans trans, It b) const {
        return boost::transform_iterator<Trans, It>(b, trans);
    }
    
    /// Transformed end-iterator
    template<typename Trans, typename It = Objects::const_iterator>
    boost::transform_iterator<Trans, It> trans_end(Trans trans, It e) const {
        return boost::transform_iterator<Trans, It>(e, trans);
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


/*
bool check_file_is_private_key(const std::string& file) {
    std::ifstream infile(file);
    std::string first_line;
    std::getline(infile, first_line, '\n');
    return first_line == "-----BEGIN RSA PRIVATE KEY-----";
}*/

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
        const auto a = p_->objects.insert(convert(*it)).first;
        st_logf("Finded obejcts: %s %lu\n", it->path().filename().c_str(), a->first);
    }
    
    const CK_OBJECT_CLASS public_key = CKO_PUBLIC_KEY;
    const CK_OBJECT_CLASS private_key = CKO_PRIVATE_KEY;
    
    for(auto private_it = p_->filter_iterator({create_object(CKA_CLASS, private_key)}); private_it != p_->filter_end(); ++private_it) {
        auto public_it = std::find_if(
            p_->filter_iterator({create_object(CKA_CLASS, public_key)}),
            p_->filter_end(),
            [&private_it](Objects::value_type& pub_key){
                return pub_key.second[CKA_LABEL].label() == (private_it->second[CKA_LABEL].label() + ".pub");
            }
        );
        
        if (public_it != p_->filter_end()) {
            public_it->second[CKA_ID] = private_it->second[CKA_ID];
        }
    }
    
//     for(auto it = p_->objects.begin(); it != p_->objects.end(); ++it) {
//         auto klass = it->second.find(CKA_CLASS);
//         if (klass != it->second.end()) {
//             if (klass->second == attribute_t(CKA_CLASS, private_key)) {
//                 
//                 auto pub = p_->find([&] (const Objects::value_type& o) {
//                     auto tmp_pub = o.second.find(CKA_LABEL);
//                     if (tmp_pub != o.second.end()) {
//                         return tmp_pub->second.label() == it->second.label() + ".pub";
//                     }
// 
//                     return false;
// 
//                 });
//                 
//                 pub->second[CKA_ID] = priv->second[CKA_ID];
//             }
//         }
//     }
    
    st_logf("Invalid obejct: %lu\n", this->handle_invalid());
    
}

soft_token_t::~soft_token_t()
{
//     std::cerr << "DESTRUCTOR 1" << std::endl;
    p_.reset();
//     std::cerr << "DESTRUCTOR 2" << std::endl;
}

bool soft_token_t::logged_in() const
{
    return false;

}

Handles soft_token_t::handles() const
{
    return Handles(
        p_->trans_iterator(boost::bind(&Objects::value_type::first,_1), p_->objects.begin()),
        p_->trans_end(boost::bind(&Objects::value_type::first,_1), p_->objects.end())
    );
}

handle_iterator_t soft_token_t::handles_iterator() const
{
    auto it = p_->trans_iterator(boost::bind(&Objects::value_type::first,_1), p_->objects.begin());
    auto end = p_->trans_end(boost::bind(&Objects::value_type::first,_1), p_->objects.end());
    
    return handle_iterator_t([it, end] () mutable {
        if (it != end) {
            return *(it++);
        }
        else {
            return static_cast<CK_OBJECT_HANDLE>(-1);  
        }
    });
}



handle_iterator_t soft_token_t::find_handles_iterator(const Attributes& attrs) const
{
    st_logf("initialize search \n");
    auto it = p_->trans_iterator(boost::bind(&Objects::value_type::first,_1), p_->filter_iterator(attrs));
    auto end = p_->trans_end(boost::bind(&Objects::value_type::first,_1), p_->filter_end());
    
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

Attributes data_object_attrs(descriptor_p desc)
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
        create_object(CKA_LABEL,     desc->filename),
        
    };

    return attributes;
}

Attributes public_key_attrs(descriptor_p desc)
{
    const CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;
    const CK_MECHANISM_TYPE mech_type = CKM_RSA_X_509;
    const CK_KEY_TYPE type = CKK_RSA;
    
    //ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-20/pkcs-11v2-20.pdf
    Attributes attributes = {
        create_object(CKA_CLASS,     klass),
        
//         std::make_pair(CKA_VALUE, attribute_t(CKA_VALUE, data.size())), // SPECIAL CASE FOR VALUE
        
        //Common Storage Object Attributes
        create_object(CKA_TOKEN,     bool_true),
        create_object(CKA_PRIVATE,   bool_false),
        create_object(CKA_MODIFIABLE,bool_false),
        create_object(CKA_LABEL,     desc->filename),
        
        //Common Key Attributes
        create_object(CKA_KEY_TYPE,  type),
        create_object(CKA_ID,        std::to_string(desc->id)),
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
    
   
    //RSA Public Key Object Attributes
    if (type == CKK_RSA) {
        EVP_PKEY *pkey = PEM_read_PUBKEY(desc->file, NULL, NULL, NULL);
        if (pkey == NULL) {
            if (FILE* converted = ::popen(std::string("ssh-keygen -f " + desc->fullname + " -e -m PKCS8").c_str(), "r")) {
                pkey = PEM_read_PUBKEY(converted, NULL, NULL, NULL);
                ::pclose(converted);
            }
        }

        if (pkey) {
            int size = 0;
            std::shared_ptr<unsigned char> buf;
            
            std::tie(size, buf) = read_bignum(pkey->pkey.rsa->n);
            attributes.insert(std::make_pair(CKA_MODULUS, attribute_t(CKA_MODULUS, buf.get(), size)));
            attributes.insert(create_object(CKA_MODULUS_BITS,   size * 8));            
            
            std::tie(size, buf) = read_bignum(pkey->pkey.rsa->e);
            attributes.insert(std::make_pair(CKA_PUBLIC_EXPONENT, attribute_t(CKA_PUBLIC_EXPONENT, buf.get(), size)));

            EVP_PKEY_free(pkey);
        }
    }
    

    return attributes;    
}

Attributes private_key_attrs(descriptor_p desc)
{
    const CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
    const CK_MECHANISM_TYPE mech_type = CKM_RSA_X_509;
    const CK_KEY_TYPE type = CKK_RSA;
    
    Attributes attributes = {
        create_object(CKA_CLASS,     klass),
        
//         std::make_pair(CKA_VALUE, attribute_t(CKA_VALUE, data.size())), // SPECIAL CASE FOR VALUE
        
        //Common Storage Object Attributes
        create_object(CKA_TOKEN,     bool_true),
        create_object(CKA_PRIVATE,   bool_true),
        create_object(CKA_MODIFIABLE,bool_false),
        create_object(CKA_LABEL,     desc->filename),
        
        //Common Key Attributes
        create_object(CKA_KEY_TYPE,  type),
        create_object(CKA_ID,        std::to_string(desc->id)),
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
    
    //RSA Private Key Object Attributes
    if (type == CKK_RSA) {
//         EVP_PKEY *pkey = PEM_read_PR(desc->file, NULL, NULL, NULL);
//         if (pkey == NULL) {
//             if (FILE* converted = ::popen(std::string("ssh-keygen -f " + desc->fullname + " -e -m PKCS8").c_str(), "r")) {
//                 pkey = PEM_read_PUBKEY(converted, NULL, NULL, NULL);
//                 ::pclose(converted);
//             }
//         }
// 
//         if (pkey) {
//             int size = 0;
//             std::shared_ptr<unsigned char> buf;
//             
//             std::tie(size, buf) = read_bignum(pkey->pkey.rsa->n);
//             attributes.insert(std::make_pair(CKA_MODULUS, attribute_t(CKA_MODULUS, buf.get(), size)));
//             attributes.insert(create_object(CKA_MODULUS_BITS,   size * 8));            
//             
//             std::tie(size, buf) = read_bignum(pkey->pkey.rsa->e);
//             attributes.insert(std::make_pair(CKA_PUBLIC_EXPONENT, attribute_t(CKA_PUBLIC_EXPONENT, buf.get(), size)));
// 
//             EVP_PKEY_free(pkey);
//         }
    }


    return attributes;
}

Attributes secret_key_attrs(descriptor_p desc)
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
        create_object(CKA_LABEL,     desc->filename),
        
        //Common Key Attributes
        //create_object(CKA_KEY_TYPE,        id),
        create_object(CKA_ID,        std::to_string(desc->id)),
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









