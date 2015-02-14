
#include <fstream>

#include <boost/filesystem.hpp>
#include <boost/iterator/filter_iterator.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/lexical_cast.hpp>

#include <boost/foreach.hpp>

#include "storage.h"
#include "tools.h"

namespace fs = boost::filesystem;
typedef boost::property_tree::ptree config_t;

typedef boost::filter_iterator<std::function<bool(const fs::directory_entry&)>, fs::directory_iterator> files_iterator;

struct fs_storage_t : storage_t {
    fs_storage_t(const config_t& c, const std::string& pin, std::shared_ptr<storage_t> s)
        : storage_t(c, s) 
    {
        path = config_.get<std::string>("path");
        st_logf("Path : %s\n", path.c_str());
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
        system(umount.c_str());
        if (start(m.c_str(), std::vector<char>(pass.begin(), pass.end())) != 0) {
            throw std::runtime_error("Can't mount: " + m);
        }        
    }
    
    ~mount_t() {
        st_logf("Umounting: %s\n", umount.c_str());
        system(umount.c_str());
    }
    
    std::string umount;
};

struct shell_storage_t : fs_storage_t {
    shell_storage_t(const config_t& c, const std::string& pin, std::shared_ptr<storage_t> s = std::shared_ptr<storage_t>())
        : fs_storage_t(c, pin, s)
    {
        const std::string mount = c.get<std::string>("mount");
        const std::string umount = c.get<std::string>("umount");
        
        st_logf("Mount: %s, Umount: %s\n", mount.c_str(), umount.c_str());
        m_.reset(new mount_t(mount, umount, pin));
    }
    
    std::shared_ptr<mount_t> m_;
};

struct cryptfs_storage_t : storage_t {
    cryptfs_storage_t(const config_t& c, const std::string& pin, std::shared_ptr<storage_t> s)
        : storage_t(c,s)
    {
        decrypt_ = "openssl enc -d -base64 " + c.get<std::string>("cipher") + " -k '" + pin + "'";
    }
    
    virtual ~cryptfs_storage_t() {
    }
    
    virtual std::list<item_t> items() {
        std::list<item_t> result;
        for(auto item: prev->items()) {
            result.push_back(decrypt(item));
        }
        
        return result;
    }
    
    virtual item_t read(const std::string& fn) {
        return decrypt(prev->read(fn));
    }
    
    
    
    item_t decrypt(const item_t& item) const {
        return item_t {
            item.fullname,
            item.filename,
            piped(decrypt_, item.data)
        };
    }
    
    std::string decrypt_;
    
};


std::shared_ptr<storage_t> storage_t::create(const config_t& config, const std::string& pin)
{
    std::shared_ptr<storage_t> storage;
    BOOST_FOREACH(auto p, config) {
        if (p.second.size() > 0) {
            if (p.second.get<std::string>("driver") == "shell") {
                storage.reset(new shell_storage_t(p.second, pin, storage));
            }
            else if (p.second.get<std::string>("driver") == "crypt") {
                storage.reset(new cryptfs_storage_t(p.second, pin, storage));
            }
        }
    }
    
    std::cerr << "data:" << storage->read("crypt").data.data() << std::endl;
    exit(-1);

    return storage;
}
