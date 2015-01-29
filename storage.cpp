
#include "storage.h"


struct fs_storage_t : storage_t {
    fs_storage_t(const boost::property_tree::ptree& config) {
        
    }
    
    virtual std::list<item_t> items(){};
    virtual item_t read(const std::string& fn){};
};


std::shared_ptr<storage_t> storage_t::create(const boost::property_tree::ptree& config)
{
    return std::shared_ptr<storage_t>(new fs_storage_t(config));
}
