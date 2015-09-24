
#include <boost/fusion/container/map.hpp>
#include <boost/fusion/include/map.hpp>
#include <boost/fusion/include/at_key.hpp>
#include <boost/fusion/include/pair.hpp>
#include <boost/foreach.hpp>

#define FUSION_MAX_MAP_SIZE 30
#define FUSION_MAX_VECTOR_SIZE 30

#include <boost/fusion/include/make_map.hpp>
#include <boost/preprocessor.hpp>

#include "pkcs11/pkcs11u.h"
#include "pkcs11/pkcs11.h"

unsigned int constexpr const_hash(char const *input) {
    return *input
        ? static_cast<unsigned int>(*input) + 33 * const_hash(input + 1)
        : 5381;
}

template <unsigned int T>
struct tag_s {
    enum {value = T};
};

template <typename Function>
Function rvcast(Function f) {return f;}

#define __ADD_TAG(r, data, elem) (tag_s<const_hash(BOOST_STRINGIZE(BOOST_PP_CAT(CK_, elem)))>)
#define __ADD_RVCAST(r, data, elem) (rvcast(elem))

#define IMPLEMENTED_FUNCTIONS (\
    C_Initialize, C_Finalize,\
    C_GetInfo, C_GetFunctionList, C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo,\
    C_GetMechanismList, C_GetMechanismInfo,\
    C_InitToken, C_InitPIN,\
    C_OpenSession, C_CloseSession,\
    C_GetSessionInfo,\
    C_Login, C_Logout,\
    C_CreateObject,\
    C_GetAttributeValue,\
    C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal,\
    C_SignInit, C_Sign, C_SignUpdate, C_SignFinal\
)

#define __TUPLE_SEQ BOOST_PP_TUPLE_TO_SEQ(IMPLEMENTED_FUNCTIONS)

#define __SEQ_WITH_CK BOOST_PP_SEQ_FOR_EACH(__ADD_TAG, 0, __TUPLE_SEQ)
#define __SEQ_WITH_RVCAST BOOST_PP_SEQ_FOR_EACH(__ADD_RVCAST, 0, __TUPLE_SEQ)

#define __TUPLE_WITH_CK BOOST_PP_SEQ_TO_TUPLE(__SEQ_WITH_CK)
#define __TUPLE_WITH_RVCAST BOOST_PP_SEQ_TO_TUPLE(__SEQ_WITH_RVCAST)


#define FUNCTION_TYPES BOOST_PP_TUPLE_REM_CTOR(BOOST_PP_TUPLE_SIZE(__TUPLE_WITH_CK), __TUPLE_WITH_CK)
#define FUNCTION_CASTS BOOST_PP_TUPLE_REM_CTOR(BOOST_PP_TUPLE_SIZE(__TUPLE_WITH_RVCAST), __TUPLE_WITH_RVCAST)

const auto functions_c = boost::fusion::make_map<FUNCTION_TYPES>(FUNCTION_CASTS);

template <typename Tag>
struct function_name_holder {
    
    function_name_holder(){};
    function_name_holder(const std::string& fn) {set_value(fn);}
    void set_value(const std::string& fn) {instance()->value_ = fn;}

    static const std::string& value() {return instance()->value_;}
    
private:
    static function_name_holder<Tag>* instance() {
        if (!p_) p_ = new function_name_holder<Tag>();
        return p_;
    };
    
    std::string value_;
    static function_name_holder<Tag>* p_;
};

template<typename Tag>
function_name_holder<Tag>* function_name_holder<Tag>::p_ = 0;


template <typename Function, typename Tag, typename Handler, typename ...Args>
CK_RV wrap_function_impl(Args... args) {
  return Handler::handle(boost::fusion::at_key<Tag>(functions_c), args...);
}

template <typename Function, typename Tag, typename Handler>
Function wrap_exceptions()
{
  return static_cast<Function>(wrap_function_impl<Function, Tag, Handler>);
}

template <typename Function, typename Tag, typename ...Args>
CK_RV wrap_not_implemented_impl(Args... args) {
  LOG("%s - not implemeted!", function_name_holder<Tag>::value().c_str());
  return CKR_FUNCTION_NOT_SUPPORTED;
}

template <typename Function, typename Tag>
Function wrap_not_implemented(const std::string& fn)
{
  function_name_holder<Tag>().set_value(fn);
  return static_cast<Function>(wrap_not_implemented_impl<Function, Tag>);
}

#define WRAP_FUNCTION(function_type, handler) wrap_exceptions<function_type, tag_s<const_hash(#function_type)>, handler>()

#define WRAP_NOT_IMPLEMENTED(function_type) wrap_not_implemented<function_type, tag_s<const_hash(#function_type)>>(#function_type)






