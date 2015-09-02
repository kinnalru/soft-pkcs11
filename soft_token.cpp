
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/md5.h>

#include <iostream>
#include <fstream>
#include <functional>

#include <boost/bind.hpp>
#include <boost/iterator/filter_iterator.hpp>
#include <boost/iterator/transform_iterator.hpp>
#include <boost/range/adaptors.hpp>
#include <boost/foreach.hpp>
#include <boost/range/algorithm.hpp>
#include <boost/lexical_cast.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/filesystem.hpp>

#include "tools.h"
#include "storage.h"
#include "soft_token.h"
#include "exceptions.h"
#include "object.h"

enum Attribute : CK_ATTRIBUTE_TYPE {
    AttrFilename = CKA_VENDOR_DEFINED + 1,
    AttrSshPublic,
    AttrSshUnpacked,
};

const CK_BBOOL bool_true = CK_TRUE;
const CK_BBOOL bool_false = CK_FALSE;

namespace fs = boost::filesystem;
using namespace boost::adaptors;

struct is_public_key : std::unary_function<descriptor_p, bool> {
    bool operator() (descriptor_p desc) {
      return desc->first_line.find("ssh-rsa") == 0
        || desc->first_line == "-----BEGIN PUBLIC KEY-----"
        || desc->first_line == "-----BEGIN RSA PUBLIC KEY-----";        
    }
};

struct is_rsa_public_key : std::unary_function<descriptor_p, bool> {
    bool operator() (descriptor_p desc) {
      return desc->first_line == "-----BEGIN PUBLIC KEY-----"
        || desc->first_line == "-----BEGIN RSA PUBLIC KEY-----";        
    }
};

struct is_ssh_public_key : std::unary_function<descriptor_p, bool> {
    bool operator() (descriptor_p desc) {
      return desc->first_line.find("ssh-rsa") == 0;
    }
};

struct is_private_key : std::unary_function<descriptor_p, bool> {
    bool operator() (descriptor_p desc) {
        return desc->first_line == "-----BEGIN RSA PRIVATE KEY-----";        
    }
};

struct is_rsa_private_key : std::unary_function<descriptor_p, bool> {
    bool operator() (descriptor_p desc) {
        return desc->first_line == "-----BEGIN RSA PRIVATE KEY-----";        
    }
};

struct to_attributes : std::unary_function<const fs::directory_entry&, Objects::value_type> {
    
    Objects& objects;
    to_attributes(Objects& o): objects(o) {
        
    }
    
    Objects::value_type operator() (const item_t& item) {
        
        descriptor_p desc(new descriptor_t(item));

        Attributes attrs = {
            create_object(AttrFilename, desc->item.filename),
        };

//         attrs = data_object_attrs(desc, attrs);

        if (is_rsa_public_key()(desc)) {
            rsa_public_key_t o = rsa_public_key_t();
            attrs = o(desc, attrs);
        }
        else if (is_ssh_public_key()(desc)) {
            ssh_public_key_t o = ssh_public_key_t();
            attrs = o(desc, attrs);

//             attrs = ssh_public_key_attrs(desc, attrs);
// 
//             {
//                 //create additional unpacked key
//                 attrs[AttrSshUnpacked] = attribute_t(AttrSshUnpacked, bool_true);
//                 attrs[CKA_OBJECT_ID] = attribute_t(CKA_OBJECT_ID,  desc->id - 1);
//                 attrs[CKA_ID] = attribute_t(CKA_ID,  desc->id - 1);
//                 objects.insert(std::make_pair(desc->id - 1, attrs)).first->first;
//             };
//             
//             attrs.erase(AttrSshUnpacked);
//             attrs.erase(CKA_VALUE);
//             attrs[CKA_OBJECT_ID] = attribute_t(CKA_OBJECT_ID,  desc->id);
//             attrs[CKA_ID] = attribute_t(CKA_ID,  desc->id);
//             attrs[CKA_LABEL] = attribute_t(CKA_LABEL, "SSH " + attrs[CKA_LABEL].to_string());
//             attrs[AttrSshPublic] = attribute_t(AttrSshPublic, bool_true);
        }
        else if (is_rsa_private_key()(desc)) {
            st_logf("      - LOADING PRIVATE [%s]\n", desc->item.filename.c_str());      
            rsa_private_key_t o = rsa_private_key_t();
            attrs = o(desc, attrs);
        }
        else if (is_rsa_private_key()(desc)) {
            rsa_private_key_t o = rsa_private_key_t();
            attrs = o(desc, attrs);
        }
        else {
            data_object_t o = data_object_t();
            attrs = o(desc, attrs);
        }
        
        st_logf("      - ID[%lu] - ID[%lu]\n", desc->id, attrs[CKA_OBJECT_ID].to_handle());      
        
        return std::make_pair(desc->id, attrs);
    }
};

struct by_attrs : std::unary_function<const Objects::value_type&, bool> {
    by_attrs(const Attributes& a) : attrs(a) {}
    
    bool operator()(const Objects::value_type& object_pair) const {
        
        CK_OBJECT_HANDLE h = object_pair.second.at(CKA_OBJECT_ID).to_handle();
        
        st_logf("    * SCAN object: %s [%lu] [%lu]\n", object_pair.second.at(CKA_LABEL).to_string().c_str(), object_pair.first, h);
        
        for (auto it = attrs.begin(); it != attrs.end(); ++it) {
            const Attributes& object_attrs = object_pair.second;
            
            st_logf("      - compare attr type:: [0x%08lx]\n", it->first);        
            
            auto fnd = object_attrs.find(it->first);
            if (fnd != object_attrs.end()) {
                if (fnd->second != it->second) {
                    st_logf("        - attr type [0x%08lx] NOT equal %lu -- %lu\n", it->first, *((CK_ULONG*)it->second->pValue), *((CK_ULONG*)fnd->second->pValue));
                    return false;
                } else {
                    st_logf("        - attr type [0x%08lx] EQUAL %lu -- %lu\n", it->first, it->second.to_handle(), fnd->second.to_handle());
                }
            }
            else {
                st_logf("        - attr type [0x%08lx] NOT FOUND\n", it->first);
                return false;
            }
        }
        
        st_logf("    * object MATCH\n");
        return true;
    };
    
private:
    const Attributes attrs;
};

typedef std::function<bool(const Objects::value_type&)> ObjectsPred;

struct not1 : std::unary_function<const Objects::value_type&, bool> {
    
    not1(ObjectsPred p) : pred(p) {}
    
    bool operator()(const Objects::value_type& object_attrs) const {
        return !pred(object_attrs);
    }
    
private:
    ObjectsPred pred;
};

struct soft_token_t::Pimpl {
  
    Pimpl() {}
    
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
    template <typename It = Objects::iterator>
    boost::filter_iterator<ObjectsPred, It> filter_iterator(ObjectsPred pred, It b = It(), It e = It()) {
        if (b == It()) {b = objects.begin();}
        if (e == It()) {e = objects.end();}
        
        return boost::filter_iterator<ObjectsPred, It>(pred, b, e);
    }
    
    /// Filter objects by attributes
    template <typename It = Objects::iterator>
    boost::filter_iterator<ObjectsPred, It> filter_iterator(const Attributes& attrs, It b = It(), It e = It()) {
        if (b == It()) {b = objects.begin();}
        if (e == It()) {e = objects.end();}
        
        return boost::filter_iterator<ObjectsPred, It>(by_attrs(attrs), b, e);
    }
   

    /// Filter end iterator
    template <typename It = Objects::iterator>
    boost::filter_iterator<ObjectsPred, It> filter_end(It e = It()) {
        if (e == It()) {e = objects.end();}
        
        return boost::filter_iterator<ObjectsPred, It>(ObjectsPred(), e, e);
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

    boost::property_tree::ptree config;
    Objects objects;
    
    std::shared_ptr<storage_t> storage;
    std::string pin;
};

int read_password(char *buf, int size, int rwflag, void *userdata) {
    std::string p;
    std::cin >> p;
    std::copy_n(p.begin(), std::min(size, static_cast<int>(p.size())), buf);
    return p.size();
}


template <typename A>
bool is_equal(CK_ATTRIBUTE_TYPE type, const A& a1, const A& a2) {
    auto it1 = a1.second.find(type);
    if (it1 != a1.second.end()) {
        auto it2 = a2.second.find(type);
        if (it2 != a2.second.end()) {
            return it1->second == it2->second;
        }
    }
    return false;
}

soft_token_t::soft_token_t(const std::string& rcfile)
    : p_(new Pimpl())
{
   
    try {
        boost::property_tree::ini_parser::read_ini(rcfile, p_->config);
    }
    catch (const std::exception& e) {
        st_logf("Error reading config file %s: %s\n", rcfile.c_str(), e.what());
        exit(-1);
    }
    
    st_logf("Config file: %s\n", rcfile.c_str());
}

bool soft_token_t::ssh_agent() const
{
    return p_->config.get<bool>("ssh-agent", false);
}

soft_token_t::~soft_token_t()
{
    p_.reset();
}

bool soft_token_t::ready() const
{
    try {
        if (!p_->storage) {
            p_->storage = storage_t::create(p_->config);
        }
        
        return p_->storage->present();
    }
    catch(...) {
        return false;
    }
}

bool soft_token_t::logged() const
{
    return p_->storage.get() && !p_->pin.empty();
}

bool soft_token_t::login(const std::string& pin)
{
    try {
        st_logf(" log 1\n");
        p_->pin = pin;
        st_logf(" log 2\n");
        check_storage();
        st_logf(" log 3\n");
        reset();
        st_logf(" log 4\n");
    }
    catch(const std::exception& e) {
        st_logf("Exception: %s\n", e.what());
        return false;
    }
    
    return true;
}

void soft_token_t::logout()
{
    p_->pin.clear();
    p_->objects.clear();
    p_->storage.reset();
}

std::string soft_token_t::full_name() const
{
    return (p_->storage) ? p_->storage->full_name() : "no storage";
}

Handles soft_token_t::handles() const
{
    return Handles(
        p_->trans_iterator(boost::bind(&Objects::value_type::first,_1), p_->objects.begin()),
        p_->trans_end(boost::bind(&Objects::value_type::first,_1), p_->objects.end())
    );
}

handle_iterator_t soft_token_t::handles_iterator()
{
    try {
      check_storage();
    }
    catch(...) {
      
    }
    const auto objects = p_->objects | transformed(boost::bind(&Objects::value_type::first,_1));
    
    auto it = boost::begin(objects);
    auto end = boost::end(objects);
    
    return handle_iterator_t([it, end] () mutable {
        if (it != end) {
            return *(it++);
        }
        else {
            soft_token_t::handle_invalid();
        }
    });
}

handle_iterator_t soft_token_t::find_handles_iterator(Attributes attrs)
{
    try {
      check_storage();
    }
    catch(...) {
      
    }
    
    const auto objects = p_->objects | filtered(by_attrs(attrs)) | transformed(boost::bind(&Objects::value_type::first,_1));
    
    auto it = boost::begin(objects);
    auto end = boost::end(objects);
    
    return handle_iterator_t([it, end] () mutable {
        if (it != end) {
            return *(it++);
        }
        else {
            return soft_token_t::handle_invalid();
        }
    });
}

CK_OBJECT_HANDLE soft_token_t::handle_invalid()
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

bool soft_token_t::has_key(CK_OBJECT_HANDLE id) const
{
    return p_->objects.find(id) != p_->objects.end();
}

bool soft_token_t::check(CK_OBJECT_HANDLE id, const Attributes& attrs) const
{
    auto it = p_->objects.find(id);
    return (it != p_->objects.end()) && by_attrs(attrs)(*it);
}

std::string soft_token_t::read(CK_OBJECT_HANDLE id)
{
    auto it = p_->objects.find(id);
    
    if (it != p_->objects.end()) {
        if (it->second[AttrSshUnpacked].to_bool()) {
            return it->second[CKA_VALUE].to_string();
        } 

        check_storage();
        const item_t item = p_->storage->read(it->second[AttrFilename].to_string());
        return std::string(item.data.begin(), item.data.end());
    }

    return std::string();
}

CK_OBJECT_HANDLE soft_token_t::write(const std::string& filename, const std::vector<unsigned char>& data, const Attributes& attrs)
{
    auto it = std::find_if(p_->objects.begin(), p_->objects.end(),
        by_attrs({create_object(AttrFilename, filename)}));
    
    if (it != p_->objects.end()) {
        return soft_token_t::handle_invalid();
    }
    
//     MetaAttributes metalist;
//     auto id = attrs.find(CKA_ID);
//     if ( id != attrs.end()) {
//       metalist[CKA_ID] = boost::lexical_cast<std::string>(id->second.to_handle());
//     }
    
    
    
    Attributes aa(attrs);
    aa[CKA_ID] = attribute_t(CKA_ID, 2);
    
    st_logf(" w 1\n");
    
    const item_t item({
        filename,
        Bytes(data.begin(), data.end()),
        aa
    });
    
    st_logf(" w 2\n");
    
    check_storage();
    st_logf(" w 3\n");
    const item_t item2 = p_->storage->write(item);
    st_logf(" w 4\n");
    const auto a = p_->objects.insert(to_attributes(p_->objects)(item2)).first;
    return a->first;
}

std::vector<unsigned char> soft_token_t::sign(CK_OBJECT_HANDLE id, CK_MECHANISM_TYPE type, CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
    auto it = p_->objects.find(id);
    
    if (it == p_->objects.end()) throw std::runtime_error("err");
    
    const auto str = read(id);
    std::vector<char> data(str.begin(), str.end());
    
    std::shared_ptr<FILE> file(
        ::fmemopen(data.data(), data.size(), "r"),
        ::fclose
    );
    
    if (EVP_PKEY *pkey = PEM_read_PrivateKey(file.get(), NULL, NULL, NULL)) {
        if (pkey->pkey.rsa == NULL) {
//             return CKR_ARGUMENTS_BAD;
            throw std::runtime_error("err");
        }
        
        //RSA_blinding_off(rsa); /* XXX RAND is broken while running in mozilla ? */
        
        std::vector<unsigned char> buffer(RSA_size(pkey->pkey.rsa));
        
        int padding, padding_len;
        
        
        switch(type) {
        case CKM_RSA_PKCS:
            padding = RSA_PKCS1_PADDING;
            padding_len = RSA_PKCS1_PADDING_SIZE;
            break;
        case CKM_RSA_X_509:
            padding = RSA_NO_PADDING;
            padding_len = 0;
            break;
        default:
            throw std::runtime_error("err");
//             ret = CKR_FUNCTION_NOT_SUPPORTED;
//             goto out;
        }
        
        
        if (pData == NULL_PTR) {
            throw std::runtime_error("err");
//             st_logf("data NULL\n");
//             ret = CKR_ARGUMENTS_BAD;
//             goto out;
        }

        
        auto len = RSA_private_encrypt(ulDataLen, pData, buffer.data(), pkey->pkey.rsa, padding);
        
        
        st_logf("private encrypt done\n");
        if (len <= 0) {
            throw std::runtime_error("err");
//             ret = CKR_DEVICE_ERROR;
//             goto out;
        }
        if (len > buffer.size()) {
            abort();
        }
        
        
        return buffer;
    }
    
    return std::vector<unsigned char>();
}

std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> parse_bignum(CK_ATTRIBUTE_TYPE key, const Attributes& attrs) {
    if (attrs.find(key) != attrs.end()) {
        return std::unique_ptr<BIGNUM, void(*)(BIGNUM*)>(
            BN_bin2bn(attrs.at(key).value<const unsigned char*>(), attrs.at(key)->ulValueLen, NULL),
            BN_free 
        );
    } else {
       return std::unique_ptr<BIGNUM, void(*)(BIGNUM*)>(NULL, BN_free); 
    }
}


std::vector<unsigned char> soft_token_t::create_key(CK_OBJECT_CLASS klass, const Attributes& attrs) const
{
    std::unique_ptr<RSA, void(*)(RSA*)> pubkey(RSA_new(), RSA_free);
    
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> modul = parse_bignum(CKA_MODULUS, attrs);
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> expon = parse_bignum(CKA_PUBLIC_EXPONENT, attrs);
    
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> priv_expon = parse_bignum(CKA_PRIVATE_EXPONENT, attrs);
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> priv_p1 = parse_bignum(CKA_PRIME_1, attrs);
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> priv_p2 = parse_bignum(CKA_PRIME_2, attrs);
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> priv_e1 = parse_bignum(CKA_EXPONENT_1, attrs);
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> priv_e2 = parse_bignum(CKA_EXPONENT_2, attrs);
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> priv_c = parse_bignum(CKA_COEFFICIENT, attrs);
    
    pubkey->e = expon.release();
    pubkey->n = modul.release();
    
    pubkey->d = priv_expon.release();
    pubkey->p = priv_p1.release();
    pubkey->q = priv_p2.release();
    pubkey->dmp1 = priv_e1.release();
    pubkey->dmq1 = priv_e2.release();
    pubkey->iqmp = priv_c.release();
    
    std::shared_ptr<EVP_PKEY> pRsaKey(
        EVP_PKEY_new(),
        EVP_PKEY_free
    );
    
    if (1 != EVP_PKEY_assign_RSA(pRsaKey.get(), pubkey.release())) {
        throw std::runtime_error("Can't assign rsa key");
    }
    
    char *dst_buf;
    size_t size;
    
    try {
        auto file = write_mem(&dst_buf, &size);
        
        if (klass == CKO_PUBLIC_KEY) {
            if (PEM_write_PUBKEY(file.get(), pRsaKey.get()) != 1) {
                st_logf("PEM_write_PUBKEY error\n");
                throw std::runtime_error("Can't create rsa key from modulus");
            }
            st_logf("PEM_write_PUBKEY OK\n");
        } else if (klass == CKO_PRIVATE_KEY) {
            if (PEM_write_PrivateKey(file.get(), pRsaKey.get(), NULL, 0, 0, NULL, NULL) != 1) {
                st_logf("PEM_write_PrivateKey error\n");
                throw std::runtime_error("Can't create rsa key from modulus");
            }
            st_logf("PEM_write_PrivateKey OK\n");
        }
    } catch(...) {
    }

    std::vector<unsigned char> ret(dst_buf, dst_buf + size);
    free(dst_buf);
    return ret;
}


void soft_token_t::check_storage()
{
    if (p_->storage && p_->storage->present()) {
        p_->storage->set_pin(p_->pin);
        st_logf("storage is ok\n");
        return;
    }
    
    if (p_->storage && !p_->storage->present()) {
        p_->objects.clear();
        p_->storage.reset();
        throw pkcs11_exception_t(CKR_DEVICE_REMOVED, "token removed");
    }
    
    if (!p_->storage) {
      
        if (p_->pin.empty()) {
            throw pkcs11_exception_t(CKR_USER_NOT_LOGGED_IN, "no pin provided");
        }

        st_logf("creating storage...\n");
        p_->storage = storage_t::create(p_->config, p_->pin);
        reset();
    }
}

void soft_token_t::reset()
{
    p_->objects.clear();
    
    st_logf(" *  RESET cheking...\n");
    check_storage();
    
    st_logf("    cheking...\n");
    to_attributes convert(p_->objects);
    for(auto item: p_->storage->items()) {
        const auto a = p_->objects.insert(convert(item)).first;
        st_logf("    Finded obejcts: %s %lu\n", item.filename.c_str(), a->first);
    }
    
    const CK_OBJECT_CLASS public_key_c = CKO_PUBLIC_KEY;
    const CK_OBJECT_CLASS private_key_c = CKO_PRIVATE_KEY;


    st_logf("    1\n");
    
    for(auto& private_key: p_->objects | filtered(by_attrs({create_object(CKA_CLASS, private_key_c)}))) {
        auto public_range = p_->objects
            | filtered(by_attrs({create_object(CKA_CLASS, public_key_c)}))
//                 | filtered(by_attrs({create_object(AttrSshPublic, bool_true)}))
            | filtered([&private_key] (const Objects::value_type& pub_key) mutable {
                return is_equal(CKA_MODULUS, pub_key, private_key)
                    || pub_key.second.at(CKA_LABEL).to_string() == (private_key.second.at(CKA_LABEL).to_string() + ".pub");
            });
        
        for (auto& public_key : public_range) {
            public_key.second[CKA_ID] = private_key.second[CKA_ID];
            public_key.second[CKA_OBJECT_ID] = private_key.second[CKA_OBJECT_ID];
        }
    }
    
    st_logf("2\n");
    
    for(auto it = p_->objects.begin(); it != p_->objects.end(); ++it ) {
//             st_logf("  *** Final obejct: %s %s - %s\n", it->second.at(CKA_LABEL)->pValue, std::to_string(it->first).c_str(), it->second.at(CKA_ID).to_string().c_str());
    }
}










