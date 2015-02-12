
#include <fstream>

#include <boost/filesystem.hpp>
#include <boost/iterator/filter_iterator.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/lexical_cast.hpp>

#include <boost/foreach.hpp>

#include "storage.h"
#include "tools.h"

namespace fs = boost::filesystem;

typedef boost::filter_iterator<std::function<bool(const fs::directory_entry&)>, fs::directory_iterator> files_iterator;

struct fs_storage_t : storage_t {
    fs_storage_t(const boost::property_tree::ptree& c, const std::string& pin)
        : storage_t(c) 
    {
        path = config_.get<std::string>("path");
        st_logf("Path : %s\n", path.c_str());
        
//         config_.put("test", "val");
//         
//         boost::property_tree::ptree p;
//         p.put("sub1", "val1");
//         
//         boost::property_tree::ptree p2;
//         p2.put("sub2", "val2");
//         
//         config_.push_back(std::make_pair("asd", p));
        
        BOOST_FOREACH(auto a, config_) {
            std::cerr << "1" << a.first<< std::endl;
        }
        
        boost::property_tree::ini_parser::write_ini(std::cerr, config_);
        
        std::cerr << "here" << std::endl;
        
        exit(0);
    }
  
    files_iterator files_begin() {
        if (fs::exists(path) && fs::is_directory(path)) {
            return files_iterator(
                [](const fs::directory_entry& d){return fs::is_regular_file(d.status());},
                fs::directory_iterator(path)
            );
        }
        return files_end();
    }
    
    files_iterator files_end() const {
        return files_iterator(fs::directory_iterator());
    }
    
    virtual std::list<item_t> items() {
        std::list<item_t> result;
        
        for(auto it = files_begin(); it != files_end(); ++it) {
            std::ifstream stream(it->path().string());
            
            result.push_back(
                item_t(
                    it->path().string(),
                    it->path().filename().string(),
                    std::vector<char>((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>())                         
                )
            );
        }
        
        return result;
    };
    virtual item_t read(const std::string& fn) {
        for(auto it = files_begin(); it != files_end(); ++it) {
            if (it->path().filename().string() == fn) {
                std::ifstream stream(it->path().string());
                return item_t(
                    it->path().string(),
                    it->path().filename().string(),
                    std::vector<char>((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>())                         
                );
            }
        }
        throw std::runtime_error("such file not found");
    };
    
    std::string path;
};

struct mount_t {
    mount_t(const std::string& m, const std::string& u, const std::string& pass)
        : umount(u)
    {
        if (start(m.c_str(), std::vector<char>(pass.begin(), pass.end())) != 0) {
            throw std::runtime_error("Can't mount: " + m);
        }        
    }
    
    ~mount_t() {
        system(umount.c_str());
    }
    
    std::string umount;
};

typedef std::shared_ptr<mount_t> mount_p;

struct mountable_storage_t : storage_t {
    mountable_storage_t(const boost::property_tree::ptree& c, const std::string& pin)
        : storage_t(c) 
    {
        BOOST_FOREACH(auto p, c) {
            if (p.first.find("mount") == 0) {
                std::string id = p.first.substr(p.first.find("_") + 1);
                std::string mount = p.second.get_value<std::string>();
                std::string umount = c.get<std::string>("umount_" + id);
        
                st_logf("Mount: %s, Umount: %s\n", mount.c_str(), umount.c_str());
                mounts.push_back(mount_p(new mount_t(mount, umount, pin)));
            }
        }
        
    }
    
    virtual std::list<item_t> items() {
        return std::list<item_t>();
    }
    
    virtual item_t read(const std::string& fn) {
//         return item_t();
    }
    
    std::list<mount_p> mounts;

};


std::shared_ptr<storage_t> storage_t::create(const boost::property_tree::ptree& config, const std::string& pin)
{
    auto driver = config.get<std::string>("driver");
    
    if (driver == "mountfs") {
        return std::shared_ptr<storage_t>(new mountable_storage_t(config.get_child("mountfs"), pin));    
    } 
    else {
        return std::shared_ptr<storage_t>(new fs_storage_t(config, pin));
    }
}
