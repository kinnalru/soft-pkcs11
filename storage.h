
#ifndef ST_STORAGE_H
#define ST_STORAGE_H

#include <memory>
#include <list>
#include <map>

#include <boost/property_tree/ptree.hpp>

#include "types.h"
#include "tools.h"

struct item_t {
    item_t(const std::string& fn, const std::vector<char>& d, const MetaAttributes& m = MetaAttributes())
        : filename(fn)
        , data(d)
        , meta(m)
    {}
    
    const std::string filename;
    const std::vector<char> data;
    MetaAttributes meta;
};

struct storage_t {
    
    virtual ~storage_t(){};
    
    static std::shared_ptr<storage_t> create(const boost::property_tree::ptree& config, const std::string& pin = std::string());
    
    std::list<item_t> items();
    virtual item_t read(const std::string& fn);
    virtual item_t write(const item_t& item);
    
    virtual bool present() const = 0;
    virtual void set_pin(const std::string& pin) = 0;
    
    std::string full_name() const {
        if (prev) {
            return name() + "|" + prev->full_name();
        }
        else {
            return name();
        }
    }


protected:
    storage_t(const std::string& n, const boost::property_tree::ptree& c, std::shared_ptr<storage_t> s = std::shared_ptr<storage_t>())
        : name_(n), prev(s), config_(c){};
    storage_t(const storage_t& other) = delete;
    storage_t& operator=(const storage_t& other) = delete;

    friend class crypt_storage_t;    
    virtual std::list<item_t> do_items() = 0;
    virtual item_t do_read(const std::string& fn) = 0;
    virtual item_t do_write(const item_t& item) = 0;
    
    const std::string& name() const {return name_;};

    std::string name_;
    std::shared_ptr<storage_t> prev;
    boost::property_tree::ptree config_;
    std::string path_;
};

struct descriptor_t {
  
    descriptor_t(const item_t& it);
    ~descriptor_t() {}
    
    const item_t item;
    std::string first_line;
    CK_OBJECT_HANDLE id;
    std::shared_ptr<FILE> file;
};


#endif
