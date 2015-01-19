
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <iostream>
#include <fstream>

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
 
    each_file(p_->config.get<std::string>("path"), [](std::string s) {
      
        std::cerr << s << " Is key: " << check_file_is_private_key(s) << std::endl;;
        return;
      
        FILE* f = fopen(s.c_str(), "r");
        
        if (f == NULL) {
            std::cerr << "Error open file:" << s << std::endl;
        }
        
        EVP_PKEY *key = PEM_read_PrivateKey(f, NULL, read_password, NULL);
        
        if (key == NULL) {
            std::cerr << "failed to read key: " << s.c_str() << " Err:"<< ERR_error_string(ERR_get_error(), NULL);
        }
    });
}

soft_token_t::~soft_token_t()
{

}

bool soft_token_t::logged_in() const
{
    return false;
}

void soft_token_t::each_file(const std::string& path, std::function<void(std::string)> f)
{
    if (fs::exists(path) && fs::is_directory(path))
    {
        for(fs::directory_iterator dir_iter(path); dir_iter != fs::directory_iterator(); ++dir_iter)
        {
            if (fs::is_regular_file(dir_iter->status()))
            {
                f(dir_iter->path().c_str());
            }
        }
    }
}

