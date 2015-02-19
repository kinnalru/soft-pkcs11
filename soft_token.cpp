
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
#include <boost/range/algorithm.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/filesystem.hpp>

#include "tools.h"
#include "storage.h"
#include "soft_token.h"
#include "exceptions.h"

enum Attribute : CK_ATTRIBUTE_TYPE {
    AttrFilename = CKA_VENDOR_DEFINED + 1,
    AttrSshPublic,
    AttrSshUnpacked,
};

const CK_BBOOL bool_true = CK_TRUE;
const CK_BBOOL bool_false = CK_FALSE;

namespace fs = boost::filesystem;
using namespace boost::adaptors;

struct descriptor_t;
typedef std::shared_ptr<descriptor_t> descriptor_p;

Attributes data_object_attrs(descriptor_p desc, const Attributes& attributes = Attributes());
Attributes public_key_attrs(descriptor_p desc,  const Attributes& attributes = Attributes());    
Attributes rsa_public_key_attrs(descriptor_p desc,  const Attributes& attributes = Attributes());
Attributes ssh_public_key_attrs(descriptor_p desc,  const Attributes& attributes = Attributes());    
Attributes private_key_attrs(descriptor_p desc, const Attributes& attributes = Attributes());
Attributes rsa_private_key_attrs(descriptor_p desc, const Attributes& attributes = Attributes());
Attributes secret_key_attrs(descriptor_p desc,  const Attributes& attributes = Attributes());

struct to_object_id : std::unary_function<const fs::directory_entry&, CK_OBJECT_HANDLE> {
    CK_OBJECT_HANDLE operator() (const fs::directory_entry& d) const {
        return static_cast<CK_OBJECT_HANDLE>(hash(d.path().filename().c_str()));
    }
    CK_OBJECT_HANDLE operator() (const std::string& filename) const {
        return static_cast<CK_OBJECT_HANDLE>(hash(filename));
    }
private:
    std::hash<std::string> hash;
};

struct descriptor_t {
  
    descriptor_t(const item_t& it)
        : item(it)
    {
        if (item.data.empty()) {
            throw std::runtime_error("There is no data in item");
        }
        
        const std::string str(item.data.begin(), item.data.end());
        std::stringstream stream(str);
        
        std::getline(stream, first_line, '\n');
        stream.seekg (0, stream.beg);
        
        id = to_object_id()(item.filename);
        
        void* src = const_cast<char*>(item.data.data());
        file.reset(
            ::fmemopen(src, item.data.size(), "r"),
            ::fclose
        );
        
        if (!file.get()) {
            throw std::runtime_error("Can't memopen data");
        }
    }
    
    ~descriptor_t() {}
    
    const item_t item;
    std::string first_line;
    CK_OBJECT_HANDLE id;
    std::shared_ptr<FILE> file;
};

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
        
        attrs = data_object_attrs(desc, attrs);
        
        if (is_public_key()(desc)) {
            attrs = public_key_attrs(desc, attrs);
        }
        if (is_rsa_public_key()(desc)) {
            attrs = rsa_public_key_attrs(desc, attrs);
        }
        if (is_ssh_public_key()(desc)) {
            
            attrs = ssh_public_key_attrs(desc, attrs);

            {
                //create additional unpacked key
                attrs[AttrSshUnpacked] = attribute_t(AttrSshUnpacked, bool_true);
                attrs[CKA_OBJECT_ID] = attribute_t(CKA_OBJECT_ID,  std::to_string(desc->id - 1));
                attrs[CKA_ID] = attribute_t(CKA_ID,  std::to_string(desc->id - 1));
                objects.insert(std::make_pair(desc->id - 1, attrs)).first->first;
            };
            
            attrs.erase(AttrSshUnpacked);
            attrs.erase(CKA_VALUE);
            attrs[CKA_OBJECT_ID] = attribute_t(CKA_OBJECT_ID,  std::to_string(desc->id));
            attrs[CKA_ID] = attribute_t(CKA_ID,  std::to_string(desc->id));
            attrs[CKA_LABEL] = attribute_t(CKA_LABEL, "SSH " + attrs[CKA_LABEL].to_string());
            attrs[AttrSshPublic] = attribute_t(AttrSshPublic, bool_true);
        }
        
        if (is_private_key()(desc)) {
            attrs = private_key_attrs(desc, attrs);
        }
        if (is_rsa_private_key()(desc)) {
            attrs = rsa_private_key_attrs(desc, attrs);
        }
        
        return std::make_pair(desc->id, attrs);
    }
};

struct by_attrs : std::unary_function<const Objects::value_type&, bool> {
    by_attrs(const Attributes& a) : attrs(a) {}
    
    bool operator()(const Objects::value_type& object_pair) const {
        
        st_logf("SEARCH FOR ID: %s %s\n", std::to_string(object_pair.first).c_str(), object_pair.second.at(CKA_LABEL).to_string().c_str());
        
        for (auto it = attrs.begin(); it != attrs.end(); ++it) {
            const Attributes& object_attrs = object_pair.second;
            
            st_logf("----- compare attr type:: %d\n", it->first);        
            
            auto fnd = object_attrs.find(it->first);
            if (fnd != object_attrs.end()) {
                if (fnd->second != it->second) {
                    st_logf("attr type %d NOT EQUAL %lu -- %lu\n", it->first, *((CK_ULONG*)it->second->pValue), *((CK_ULONG*)fnd->second->pValue));
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
        p_->pin = pin;
        check_storage();
        reset();
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

CK_OBJECT_HANDLE soft_token_t::write(const std::string& filename, const std::string& data)
{
    auto it = std::find_if(p_->objects.begin(), p_->objects.end(),
        by_attrs({create_object(AttrFilename, filename)}));
    
    if (it != p_->objects.end()) {
        return soft_token_t::handle_invalid();
    }
    
    const item_t item({
        filename,
        std::vector<char>(data.begin(), data.end())
    });
    
    check_storage();
    const item_t item2 = p_->storage->write(item);
    
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
    
    st_logf("cheking...\n");
    check_storage();
    
    st_logf("cheking... OK\n");
    to_attributes convert(p_->objects);
    for(auto item: p_->storage->items()) {
        const auto a = p_->objects.insert(convert(item)).first;
        st_logf("Finded obejcts: %s %lu\n", item.filename.c_str(), a->first);
    }
    
    const CK_OBJECT_CLASS public_key_c = CKO_PUBLIC_KEY;
    const CK_OBJECT_CLASS private_key_c = CKO_PRIVATE_KEY;
    
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
    
    for(auto it = p_->objects.begin(); it != p_->objects.end(); ++it ) {
//             st_logf("  *** Final obejct: %s %s - %s\n", it->second.at(CKA_LABEL)->pValue, std::to_string(it->first).c_str(), it->second.at(CKA_ID).to_string().c_str());
    }
}

Attributes data_object_attrs(descriptor_p desc, const Attributes& attributes)
{
    const CK_OBJECT_CLASS klass = CKO_DATA;
    const CK_FLAGS flags = 0;
    
    
    Attributes attrs = {
        create_object(CKA_CLASS,     klass),

        //Common Storage Object Attributes
        create_object(CKA_TOKEN,     bool_true),
        create_object(CKA_PRIVATE,   bool_true),
        create_object(CKA_MODIFIABLE,bool_false),
        create_object(CKA_LABEL,     desc->item.filename),
        
        //Data Object Attributes
        //create_object(CKA_APPLICATION, desc->id),
        create_object(CKA_OBJECT_ID, std::to_string(desc->id)),
        //create_object(CKA_VALUE, desc->id), //read when needed
    };

    //keys in attrs takes precedence with attributes
    attrs.insert(attributes.begin(), attributes.end());
    
    return attrs;
}

Attributes public_key_attrs(descriptor_p desc, const Attributes& attributes)
{
    const CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;
    const CK_MECHANISM_TYPE mech_type = CKM_RSA_X_509;
    
    //ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-20/pkcs-11v2-20.pdf
    Attributes attrs = {
        create_object(CKA_CLASS,     klass),
        
        //Common Storage Object Attributes
        create_object(CKA_TOKEN,     bool_true),
        create_object(CKA_PRIVATE,   bool_false),
        create_object(CKA_MODIFIABLE,bool_false),
        create_object(CKA_LABEL,     desc->item.filename),
        
        //Common Key Attributes
        //create_object(CKA_KEY_TYPE,  type),
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
    
   
    //keys in attrs takes precedence with attributes
    attrs.insert(attributes.begin(), attributes.end());

    return attrs;    
}

Attributes rsa_public_key_attrs(descriptor_p desc, const Attributes& attributes)
{
    const CK_KEY_TYPE type = CKK_RSA;
    
    Attributes attrs = {
        create_object(CKA_KEY_TYPE,  type),
    };
    
    if (EVP_PKEY *pkey = PEM_read_PUBKEY(desc->file.get(), NULL, NULL, NULL)) {
        int size = 0;
        std::shared_ptr<unsigned char> buf;
        
        std::tie(size, buf) = read_bignum(pkey->pkey.rsa->n);
        attrs.insert(std::make_pair(CKA_MODULUS, attribute_t(CKA_MODULUS, buf.get(), size)));
        attrs.insert(create_object(CKA_MODULUS_BITS,   size * 8));            
        
        std::tie(size, buf) = read_bignum(pkey->pkey.rsa->e);
        attrs.insert(std::make_pair(CKA_PUBLIC_EXPONENT, attribute_t(CKA_PUBLIC_EXPONENT, buf.get(), size)));

        EVP_PKEY_free(pkey);
    }
    
    //keys in attrs takes precedence with attributes
    attrs.insert(attributes.begin(), attributes.end());

    return attrs;  
}



Attributes ssh_public_key_attrs(descriptor_p desc, const Attributes& attributes)
{
    Attributes attrs;
    const auto data = piped("cat > /tmp/.soft-pkcs.tmp && ssh-keygen -e -m PKCS8 -f /tmp/.soft-pkcs.tmp && rm /tmp/.soft-pkcs.tmp", desc->item.data);
    
    assert(data.size());
    
    if (!data.empty()) {
        std::shared_ptr<FILE> reserve = desc->file;        
        desc->file =read_mem(data);
        attrs = rsa_public_key_attrs(desc, attributes);
        desc->file = reserve;

        attrs.insert(create_object(CKA_VALUE, data));        
    }
    
    //keys in attrs takes precedence with attributes
    attrs.insert(attributes.begin(), attributes.end());
    
    return attrs;  
}

Attributes private_key_attrs(descriptor_p desc, const Attributes& attributes)
{
    const CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
    const CK_MECHANISM_TYPE mech_type = CKM_RSA_X_509;
    const CK_KEY_TYPE type = CKK_GENERIC_SECRET;
    
    Attributes attrs = {
        create_object(CKA_CLASS,     klass),
        
//         std::make_pair(CKA_VALUE, attribute_t(CKA_VALUE, data.size())), // SPECIAL CASE FOR VALUE
        
        //Common Storage Object Attributes
        create_object(CKA_TOKEN,     bool_true),
        create_object(CKA_PRIVATE,   bool_true),
        create_object(CKA_MODIFIABLE,bool_false),
        create_object(CKA_LABEL,     desc->item.filename),
        
        //Common Key Attributes
        create_object(CKA_KEY_TYPE,  type),
        create_object(CKA_ID,        std::to_string(desc->id)),
        //create_object(CKA_START_DATE,      id),
        //create_object(CKA_END_DATE,        id),
        create_object(CKA_DERIVE,    bool_false),
        create_object(CKA_LOCAL,     bool_false),
        create_object(CKA_KEY_GEN_MECHANISM, mech_type),
        
        //Common Private Key Attributes
        //create_object(CKA_SUBJECT,   bool_true),
        create_object(CKA_SENSITIVE, bool_true),
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
    
    //keys in attrs takes precedence with attributes 
    attrs.insert(attributes.begin(), attributes.end());

    return attrs;  
}

Attributes rsa_private_key_attrs(descriptor_p desc, const Attributes& attributes) {
    const CK_KEY_TYPE type = CKK_RSA;
    
    Attributes attrs = {
        create_object(CKA_KEY_TYPE,  type),
    };
    
    if (EVP_PKEY *pkey = PEM_read_PrivateKey(desc->file.get(), NULL, NULL, const_cast<char*>(""))) {
        int size = 0;
        std::shared_ptr<unsigned char> buf;
        
        std::tie(size, buf) = read_bignum(pkey->pkey.rsa->n);
        attrs.insert(std::make_pair(CKA_MODULUS, attribute_t(CKA_MODULUS, buf.get(), size)));
        
        std::tie(size, buf) = read_bignum(pkey->pkey.rsa->e);
        attrs.insert(std::make_pair(CKA_PUBLIC_EXPONENT, attribute_t(CKA_PUBLIC_EXPONENT, buf.get(), size)));

        EVP_PKEY_free(pkey);
    }
    
    //keys in attrs takes precedence with attributes
    attrs.insert(attributes.begin(), attributes.end());

    return attrs; 
}

Attributes secret_key_attrs(descriptor_p desc, const Attributes& attributes)
{
    const CK_OBJECT_CLASS klass = CKO_SECRET_KEY;
    const CK_MECHANISM_TYPE mech_type = CKM_RSA_X_509;
    
    //ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-20/pkcs-11v2-20.pdf
    Attributes attrs = {
        create_object(CKA_CLASS,     klass),
        
//         std::make_pair(CKA_VALUE, attribute_t(CKA_VALUE, data.size())), // SPECIAL CASE FOR VALUE
        
        //Common Storage Object Attributes
        create_object(CKA_TOKEN,     bool_true),
        create_object(CKA_PRIVATE,   bool_true),
        create_object(CKA_MODIFIABLE,bool_false),
        create_object(CKA_LABEL,     desc->item.filename),
        
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

    //keys in attrs takes precedence with attributes
    attrs.insert(attributes.begin(), attributes.end());

    return attrs;
}









