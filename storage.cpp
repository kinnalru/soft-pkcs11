
#include <fstream>

#include <boost/filesystem.hpp>
#include <boost/iterator/filter_iterator.hpp>

#include "storage.h"
#include "tools.h"

namespace fs = boost::filesystem;

typedef boost::filter_iterator<std::function<bool(const fs::directory_entry&)>, fs::directory_iterator> files_iterator;

struct fs_storage_t : storage_t {
    fs_storage_t(const boost::property_tree::ptree& c)
        : storage_t(c) 
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


std::shared_ptr<storage_t> storage_t::create(const boost::property_tree::ptree& c)
{
    return std::shared_ptr<storage_t>(new fs_storage_t(c));
}
