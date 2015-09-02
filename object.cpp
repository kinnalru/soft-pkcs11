
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/md5.h>

#include <boost/lexical_cast.hpp>

#include "tools.h"
#include "storage.h"
#include "object.h"


const CK_BBOOL bool_true = CK_TRUE;
const CK_BBOOL bool_false = CK_FALSE;

Attributes data_object_t::operator()(descriptor_p desc, const Attributes& attributes) const
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
        create_object(CKA_OBJECT_ID,  desc->id),
        //create_object(CKA_VALUE, desc->id), //read when needed
    };

    //keys in attrs takes precedence with attributes
    attrs.insert(attributes.begin(), attributes.end());
    
    return attrs;
}

Attributes public_key_t::operator()(descriptor_p desc, const Attributes& attributes) const
{
    const Attributes base_attrs = data_object_t::operator()(desc, attributes);

    const CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;
    const CK_MECHANISM_TYPE mech_type = CKM_RSA_X_509;    
    
    CK_ULONG id = desc->id;
    
    if (desc->item.meta.find(CKA_ID) != desc->item.meta.end()) {
      id = boost::lexical_cast<CK_ULONG>(desc->item.meta.find(CKA_ID)->second);
    }
    
    st_logf("\n\n\nID FROM META: %lu\n", id);
    
    Attributes attrs = {
        create_object(CKA_CLASS,     klass),
        
        //Common Storage Object Attributes
        create_object(CKA_TOKEN,     bool_true),
        create_object(CKA_PRIVATE,   bool_false),
        create_object(CKA_MODIFIABLE,bool_false),
        create_object(CKA_LABEL,     desc->item.filename),
        
        //Common Key Attributes
        //create_object(CKA_KEY_TYPE,  type),
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
   
    //keys in attrs takes precedence with attributes
    attrs.insert(base_attrs.begin(), base_attrs.end());

    return attrs;    
}

Attributes rsa_public_key_t::operator()(descriptor_p desc, const Attributes& attributes) const
{
    const Attributes base_attrs = public_key_t::operator()(desc, attributes);

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
    attrs.insert(base_attrs.begin(), base_attrs.end());

    return attrs;  
}


Attributes ssh_public_key_t::operator()(descriptor_p desc, const Attributes& attributes) const
{
    Attributes attrs;
    const auto data = piped("cat > /tmp/.soft-pkcs.tmp && ssh-keygen -e -m PKCS8 -f /tmp/.soft-pkcs.tmp && rm /tmp/.soft-pkcs.tmp", desc->item.data);
    
    assert(data.size());
    
    if (!data.empty()) {
        std::shared_ptr<FILE> reserve = desc->file;        
        desc->file =read_mem(data);
        attrs = rsa_public_key_t::operator()(desc, attributes);
        desc->file = reserve;

        attrs.insert(create_object(CKA_VALUE, data));        
    }
    
    return attrs;  
}

Attributes private_key_t::operator()(descriptor_p desc, const Attributes& attributes) const
{
    const Attributes base_attrs = data_object_t::operator()(desc, attributes);
    
    const CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
    const CK_MECHANISM_TYPE mech_type = CKM_RSA_X_509;
    const CK_KEY_TYPE type = CKK_GENERIC_SECRET;
    
    
    CK_ULONG id = desc->id;
    
    if (desc->item.meta.find(CKA_ID) != desc->item.meta.end()) {
      id = boost::lexical_cast<CK_ULONG>(desc->item.meta.find(CKA_ID)->second);
    }
    
    st_logf("\n\n\nID FROM META: %lu\n", id);
    
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
        create_object(CKA_ID,        id),
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
    attrs.insert(base_attrs.begin(), base_attrs.end());

    return attrs;  
}

Attributes rsa_private_key_t::operator()(descriptor_p desc, const Attributes& attributes) const
{
    const Attributes base_attrs = private_key_t::operator()(desc, attributes);

    const CK_KEY_TYPE type = CKK_RSA;
    
    Attributes attrs = {
        create_object(CKA_KEY_TYPE,  type),
    };
    
    st_logf("  ..... before\n");
    if (EVP_PKEY *pkey = PEM_read_PrivateKey(desc->file.get(), NULL, NULL, const_cast<char*>(""))) {
        int size = 0;
        std::shared_ptr<unsigned char> buf;
        
        std::tie(size, buf) = read_bignum(pkey->pkey.rsa->n);
        attrs.insert(std::make_pair(CKA_MODULUS, attribute_t(CKA_MODULUS, buf.get(), size)));
        
         st_logf("  ..... CKA_MODULUS: %lu\n", attrs[CKA_MODULUS].to_handle());
        
        std::tie(size, buf) = read_bignum(pkey->pkey.rsa->e);
        attrs.insert(std::make_pair(CKA_PUBLIC_EXPONENT, attribute_t(CKA_PUBLIC_EXPONENT, buf.get(), size)));

        EVP_PKEY_free(pkey);
    }
    st_logf("  ..... after\n");
    
    //keys in attrs takes precedence with attributes
    attrs.insert(base_attrs.begin(), base_attrs.end());

    return attrs; 
}

Attributes secrete_key_t::operator()(descriptor_p desc, const Attributes& attributes) const
{
    const Attributes base_attrs = data_object_t::operator()(desc, attributes);

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
        create_object(CKA_ID,        desc->id),
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









