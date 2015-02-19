
#ifndef ST_STORAGE_H
#define ST_STORAGE_H

#include <memory>
#include <list>

#include <boost/property_tree/ptree.hpp>

#include "tools.h"

struct item_t {
    item_t(const std::string& fn, const std::vector<char>& d)
        : filename(fn)
        , data(d)
    {}
    
    const std::string filename;
    const std::vector<char> data;
};

struct storage_t {
    
    virtual ~storage_t(){};
    
    static std::shared_ptr<storage_t> create(const boost::property_tree::ptree& config, const std::string& pin = std::string());
    
    virtual bool present() const = 0;
    virtual std::list<item_t> items() = 0;
    virtual item_t read(const std::string& fn) = 0;
    virtual item_t write(const item_t& item) = 0;
    
    virtual void set_pin(const std::string& pin) = 0;
    
    std::string full_name() const {
      return "none";
        std::cerr << "fn: " << this << std::endl;
        if (prev) {
            std::cerr << "name: " << name() << std::endl;
            std::cerr << "prev: " << prev->full_name() << std::endl;
            return name() + "|" + prev->full_name();
        }
        else {
            std::cerr << "name last: " << name() << std::endl;
            return name();
        }
    }

protected:
    storage_t(const boost::property_tree::ptree& c, std::shared_ptr<storage_t> s = std::shared_ptr<storage_t>()) : prev(s), config_(c){};
    storage_t(const storage_t& other) = delete;
    storage_t& operator=(const storage_t& other) = delete;
    
    virtual std::string name() const {return "none";};

    std::shared_ptr<storage_t> prev;
    boost::property_tree::ptree config_;
    std::string path_;
};


#endif
