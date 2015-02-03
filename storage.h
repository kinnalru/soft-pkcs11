
#ifndef ST_STORAGE_H
#define ST_STORAGE_H

#include <memory>
#include <list>

#include <boost/property_tree/ptree.hpp>

#include "tools.h"

struct item_t {
    item_t(const std::string& full, const std::string& fn, const std::vector<char>& d)
        : fullname(full)
        , filename(fn)
        , data(d)
    {}
    
    const std::string fullname; //FIXME HACK remove
    const std::string filename;
    const std::vector<char> data;
};

struct storage_t {
    
    virtual ~storage_t(){};
    
    static std::shared_ptr<storage_t> create(const boost::property_tree::ptree& config);
    
    virtual std::list<item_t> items() = 0;
    virtual item_t read(const std::string& fn) = 0;
    

protected:
    storage_t(const boost::property_tree::ptree& c) : config_(c){};
    storage_t(const storage_t& other) = delete;
    storage_t& operator=(const storage_t& other) = delete;
    
    boost::property_tree::ptree config_;
};


#endif
