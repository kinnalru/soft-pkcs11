
#include <fstream>

#include <boost/filesystem.hpp>

#include "storage.h"
#include "tools.h"

namespace fs = boost::filesystem;


struct fs_storage_t : storage_t {
    fs_storage_t(const boost::property_tree::ptree& c)
        : storage_t(c) 
    {
        path = config_.get<std::string>("path");
        st_logf("Path : %s\n", path.c_str());
    }
    
    virtual std::list<item_t> items() {
      
        std::list<item_t> result;
      
        if (fs::exists(path) && fs::is_directory(path)) {
          
            for (auto it = fs::directory_iterator(path); it != fs::directory_iterator(); ++it) {
                if (fs::is_regular_file(it->status())) {
                  std::ifstream stream(it->path().string());
                  
                  result.push_back(
                      item_t(
                          it->path().string(),
                          it->path().filename().string(),
                          std::vector<char>((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>())                         
                      )
                  );
                }
            }
        }
        
        return result;
    };
    virtual item_t read(const std::string& fn) {
        if (fs::exists(path) && fs::is_directory(path)) {
          
            for (auto it = fs::directory_iterator(path); it != fs::directory_iterator(); ++it) {
                if (fs::is_regular_file(it->status())) {
                  if (it->path().filename().string() == fn) {
                      std::ifstream stream(it->path().string());
                      return item_t(
                          it->path().string(),
                          it->path().filename().string(),
                          std::vector<char>((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>())                         
                      );
                  }
                }
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
