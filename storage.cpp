
#include <fstream>

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/iterator/filter_iterator.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ini_parser.hpp>

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
                    it->path().filename().string(),
                    std::vector<char>((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>())                         
                );
            }
        }
        throw std::runtime_error("such file not found");
    };
    
    virtual item_t write(const item_t& item) {
        std::shared_ptr<FILE> file(
            ::fopen((fs::directory_entry(path).path() / (item.filename)).native().c_str(), "w+"),
            ::fclose
        );
        
        if (!file.get()) {
            throw std::runtime_error("can't open file for writing");
        }
        
        int res = ::fwrite(item.data.data(), 1, item.data.size(), file.get());
        if (res != item.data.size()) {
            throw std::runtime_error("can't write file");
        }
        
        file.reset();
        
        return read(item.filename);
    }
    
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

struct fuse_storage_t : fs_storage_t {
    fuse_storage_t(const config_t& c, const std::string& pin, std::shared_ptr<storage_t> s = std::shared_ptr<storage_t>())
        : fs_storage_t(c, pin, s)
    {
        const std::string mount = c.get<std::string>("mount");
        const std::string umount = c.get<std::string>("umount");
        
        st_logf("Mount: %s, Umount: %s\n", mount.c_str(), umount.c_str());
        m_.reset(new mount_t(mount, umount, pin));
    }
    
    std::shared_ptr<mount_t> m_;
};

struct crypt_storage_t : storage_t {
    crypt_storage_t(const config_t& c, const std::string& pin, std::shared_ptr<storage_t> s)
        : storage_t(c, s)
    {
        encrypt_ = c.get<std::string>("encrypt");        
        decrypt_ = c.get<std::string>("decrypt");
        
        boost::replace_all(encrypt_, "%PIN%", pin);
        boost::replace_all(decrypt_, "%PIN%", pin);
    }
    
    virtual ~crypt_storage_t() {
    }
    
    virtual std::list<item_t> items() {
        std::list<item_t> result;
        for(auto item: prev->items()) {
            const item_t d = decrypt(item);
            if (!d.data.empty()) {
                result.push_back(d);
            }
        }
        
        return result;
    }
    
    virtual item_t read(const std::string& fn) {
        return decrypt(prev->read(fn));
    }
    
    virtual item_t write(const item_t& item) {
        return decrypt(prev->write(encrypt(item)));
    }
    
    
    
    item_t decrypt(const item_t& item) const {
        return item_t {
            item.filename,
            piped(decrypt_, item.data)
        };
    }
    
    item_t encrypt(const item_t& item) const {
        return item_t {
            item.filename,
            piped(encrypt_, item.data)
        };
    }
    
    std::string decrypt_;
    std::string encrypt_;
    
};


std::shared_ptr<storage_t> storage_t::create(const config_t& config, const std::string& pin)
{
    std::shared_ptr<storage_t> storage;
    BOOST_FOREACH(auto p, config) {
        if (p.second.size() > 0) {
            if (p.second.get<std::string>("driver") == "fs") {
                storage.reset(new fs_storage_t(p.second, pin, storage));
            }
            else if (p.second.get<std::string>("driver") == "fuse") {
                storage.reset(new fuse_storage_t(p.second, pin, storage));
            }
            else if (p.second.get<std::string>("driver") == "crypt") {
                storage.reset(new crypt_storage_t(p.second, pin, storage));
            }
        }
    }
    
    return storage;
}
