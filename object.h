
#include "types.h"


struct object_t {
    virtual ~object_t(){}
    
    virtual Attributes operator()(descriptor_p desc, const Attributes& attributes) const = 0;
};

struct data_object_t: public object_t {
    Attributes operator()(descriptor_p desc, const Attributes& attributes) const;
};


struct public_key_t: public data_object_t {
    Attributes operator()(descriptor_p desc, const Attributes& attributes) const;
};

struct rsa_public_key_t: public public_key_t {
    Attributes operator()(descriptor_p desc, const Attributes& attributes) const;
};

struct ssh_public_key_t: public rsa_public_key_t {
    Attributes operator()(descriptor_p desc, const Attributes& attributes) const;
};


struct private_key_t: public data_object_t {
    Attributes operator()(descriptor_p desc, const Attributes& attributes) const;
};

struct rsa_private_key_t: public private_key_t {
    Attributes operator()(descriptor_p desc, const Attributes& attributes) const;
};


struct secrete_key_t: public data_object_t {
    Attributes operator()(descriptor_p desc, const Attributes& attributes) const;
};





