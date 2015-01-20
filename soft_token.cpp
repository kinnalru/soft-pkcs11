
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <iostream>
#include <fstream>
#include <functional>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/filesystem.hpp>

#include "soft_token.h"



namespace fs = boost::filesystem;

struct soft_token_t::Pimpl {
  
    Pimpl() {
      config.put("path", "default");
    }
  
    boost::property_tree::ptree config;
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
    std::cerr <<"config: " << rcfile << std::endl;
    
    try {
      boost::property_tree::ini_parser::read_ini(rcfile, p_->config);
    }
    catch (...) {}
 
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

std::vector<CK_ULONG> soft_token_t::object_ids() const
{
    std::vector<CK_ULONG> result;
    std::hash<std::string> hash;
    each_file(p_->config.get<std::string>("path"), [&result, &hash] (std::string s) {
        if (check_file_is_private_key(s)) {
            std::ifstream t(s);
            std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
            result.push_back(hash(str));
        }
        
        return false;
    });
    return result;
}

std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> soft_token_t::attributes(CK_ULONG id) const
{
    std::hash<std::string> hash;
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> result;
    each_file(p_->config.get<std::string>("path"), [&] (std::string s) {
        if (check_file_is_private_key(s)) {
            std::ifstream t(s);
            std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
            if (hash(str) == id) {
                std::cerr << "ID found:" << id << std::endl;
                result = read_attributes(s, str, id);
                return true;
            }
        }
        
        return false;
    });
    return result;
}

 
inline CK_ATTRIBUTE create_object(CK_ATTRIBUTE_TYPE type, CK_VOID_PTR src, CK_ULONG len) {
    CK_ATTRIBUTE attr = {type, malloc(len), len}; 
    if (!attr.pValue) throw std::bad_alloc();
    memcpy(attr.pValue, src, len);
    return attr;
}

std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> soft_token_t::read_attributes(const std::string& file, const std::string& data, CK_ULONG& id) const
{
//     std::cerr << file << std::endl;
    
    CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
    CK_BBOOL bool_true = CK_TRUE;
    CK_BBOOL bool_false = CK_FALSE;
    CK_MECHANISM_TYPE mech_type = CKM_RSA_X_509;
    CK_FLAGS flags = 0;
    
   
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE> attributes = {
        {CKA_CLASS, create_object(CKA_CLASS,     &klass, sizeof(klass))},
        {CKA_TOKEN, create_object(CKA_TOKEN,     &bool_true, sizeof(bool_true))},
        {CKA_PRIVATE, create_object(CKA_PRIVATE,   &bool_false, sizeof(bool_false))},
        {CKA_MODIFIABLE, create_object(CKA_MODIFIABLE,&bool_false, sizeof(bool_false))},
        {CKA_LABEL, create_object(CKA_LABEL,     file.c_str(), file.size() + 1)},
         
        {CKA_ID, create_object(CKA_ID,      &id, sizeof(id))},
        {CKA_DERIVE, create_object(CKA_DERIVE,  &bool_false, sizeof(bool_false))},
        {CKA_LOCAL, create_object(CKA_LOCAL,   &bool_false, sizeof(bool_false))},
        {CKA_KEY_GEN_MECHANISM, create_object(CKA_KEY_GEN_MECHANISM, &mech_type, sizeof(mech_type))},
        
        {CKA_SENSITIVE, create_object(CKA_SENSITIVE, &bool_true, sizeof(bool_true))},
        {CKA_SECONDARY_AUTH, create_object(CKA_SECONDARY_AUTH, &bool_false, sizeof(bool_false))},
        
        {CKA_AUTH_PIN_FLAGS, create_object(CKA_AUTH_PIN_FLAGS, &flags, sizeof(flags))},
        {CKA_DECRYPT, create_object(CKA_DECRYPT, &bool_true, sizeof(bool_true))},
        
        {CKA_SIGN, create_object(CKA_SIGN, &bool_true, sizeof(bool_true))},
        {CKA_SIGN_RECOVER, create_object(CKA_SIGN_RECOVER, &bool_false, sizeof(bool_false))},
        {CKA_UNWRAP, create_object(CKA_UNWRAP, &bool_true, sizeof(bool_true))},
        {CKA_EXTRACTABLE, create_object(CKA_EXTRACTABLE, &bool_true, sizeof(bool_true))},
        {CKA_NEVER_EXTRACTABLE, create_object(CKA_NEVER_EXTRACTABLE, &bool_false, sizeof(bool_false))},
    };
    

    
    return attributes;
     
//     add_object_attribute(o, 0, CKA_KEY_TYPE, &key_type, sizeof(key_type));

//     add_object_attribute(o, 0, CKA_START_DATE, "", 1); /* XXX */
//     add_object_attribute(o, 0, CKA_END_DATE, "", 1); /* XXX */

// 
//     add_object_attribute(o, 0, CKA_SUBJECT, subject_data, subject_length);


}




bool soft_token_t::logged_in() const
{
    return false;
}

void soft_token_t::each_file(const std::string& path, std::function<bool(std::string)> f) const
{
    if (fs::exists(path) && fs::is_directory(path))
    {
        fs::directory_iterator end_it = fs::directory_iterator();
        for(fs::directory_iterator dir_iter(path); dir_iter != end_it; ++dir_iter)
        {
            if (fs::is_regular_file(dir_iter->status()))
            {
                std::cerr << dir_iter->path() << std::endl;
                if (f(dir_iter->path().c_str())) return;
            }
        }
    }
}



