
#include <fstream>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/iterator/filter_iterator.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ini_parser.hpp>

#include <boost/interprocess/streams/vectorstream.hpp>


#include "storage.h"
#include "tools.h"
#include "exceptions.h"

namespace fs = boost::filesystem;
typedef boost::property_tree::ptree config_t;
typedef boost::filter_iterator<std::function<bool(const fs::directory_entry&)>, fs::directory_iterator> files_iterator;

const std::string fs_driver_c = "fs";
const std::string fuse_driver_c = "fuse";
const std::string shell_driver_c = "shell";
const std::string crypt_driver_c = "crypt";

const std::string meta_c = ".soft-pkcs.meta";

std::string metaname(const std::string& file) {
    return "." + file + ".meta";
};

const std::map<std::string, CK_ATTRIBUTE_TYPE> s2a = {
  {"id", CKA_ID}
};

const std::map<CK_ATTRIBUTE_TYPE, std::string> a2s = {
  {CKA_ID, "id"}
};

Attributes parse_meta(const Bytes& bytes) {
    Attributes attributes;
    boost::property_tree::ptree ini;
    
    boost::interprocess::basic_vectorstream<Bytes> stream(bytes);
    boost::property_tree::ini_parser::read_ini(stream, ini);
    
    BOOST_FOREACH(auto attr, ini) {
        auto it = s2a.find(attr.first);
        if (it != s2a.end()) {
            attributes[it->second] = attribute_t(it->second, boost::lexical_cast<CK_ULONG>(attr.second.data()));
        }
    }
    
    return attributes;
}

Bytes write_meta(const Attributes& attributes) {
    boost::property_tree::ptree ini;
    
    BOOST_FOREACH(auto& attr, attributes) {
        auto it = a2s.find(attr.first);
        if (it != a2s.end()) {
            ini.put(it->second, boost::lexical_cast<std::string>(attr.second.to_id()));
        }
    }
    
    boost::interprocess::basic_vectorstream<Bytes> stream;
    boost::property_tree::ini_parser::write_ini(stream, ini);    
    
    return stream.vector();
}
/*
std::list<item_t> storage_t::items()
{
    std::list<item_t> items = do_items();
    
//     try {
//       MetaAttributesList metalist = parse_meta(do_read(meta_c).data);
//       BOOST_FOREACH(item_t& item, items) {
//         item.meta = metalist[item.filename];
//       }
//     }
//     catch (...) {};
    return items;
}

item_t storage_t::read(const std::string& fn)
{
    item_t item = do_read(fn);
//     try {
//       MetaAttributesList metalist = parse_meta(do_read(meta_c).data);
//       item.meta = metalist[item.filename];
//     }
//     catch(...){}
    return item;
}

item_t storage_t::write(const item_t& item)
{
//     try {
//       MetaAttributesList metalist = parse_meta(do_read(meta_c).data);
//       metalist[item.filename] = item.meta;
//       auto data = write_meta(metalist);
//       do_write(item_t(meta_c, data));
//     }
//     catch(...) {}
    return do_write(item);
}*/



struct fs_storage_t : storage_t {
    fs_storage_t(const config_t& c, const std::string& pin, std::shared_ptr<storage_t> s)
        : storage_t(fs_driver_c, c, s)
    {
        set_pin(pin);
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
    
    virtual void set_pin(const std::string& pin) {
        if (prev) prev->set_pin(pin);
    }
    
    virtual bool present() const {
        return fs::exists(path) && fs::is_directory(path);
    }
    
    virtual std::list<item_t> items() {
        std::list<item_t> result;
        
        for(auto it = files_begin(); it != files_end(); ++it) {
            std::ifstream stream(it->path().string());
            
            if (!boost::algorithm::ends_with(it->path().filename().string(), ".meta")) {
                const std::string fn = it->path().filename().string();
                result.push_back(
                    item_t(
                        fn,
                        read_file((fs::directory_entry(path).path() / fn).string()),
                        parse_meta(read_file((fs::directory_entry(path).path() / metaname(fn)).string()))                        
                    )
                );  
            }
        }
        
        return result;
    };
    
    virtual item_t read(const std::string& fn) {
        return item_t(
            fn,
            read_file((fs::directory_entry(path).path() / fn).string()),
            parse_meta(read_file((fs::directory_entry(path).path() / metaname(fn)).string()))
        );
        throw std::runtime_error("such file not found");
    };
    
    virtual item_t write(const item_t& item) {
        write_file((fs::directory_entry(path).path() / (item.filename)).string(), item.data);
        write_file((fs::directory_entry(path).path() / metaname(item.filename)).string(), write_meta(item.attributes));
        
        return read(item.filename);
    }
    
    Bytes read_file(const std::string& filepath) {
        try {
            std::ifstream stream(filepath);
            return Bytes((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        }
        catch(...) {
            return Bytes();
        }
    }
    
    void write_file(const std::string& filepath, const Bytes& data) {
        std::shared_ptr<FILE> file(
            ::fopen(filepath.c_str(), "w+"),
            ::fclose
        );
        
        if (!file.get()) {
            throw std::runtime_error("can't open file for writing");
        }
        
        int res = ::fwrite(data.data(), 1, data.size(), file.get());
        if (res != data.size()) {
            throw std::runtime_error("can't write file");
        }
        
        file.reset();
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
        name_ = fuse_driver_c;
        set_pin(pin);
    }
    
    virtual void set_pin(const std::string& pin) {
        const std::string mount = config_.get<std::string>("mount");
        const std::string umount = config_.get<std::string>("umount");      
        
        st_logf("Mount: %s, Umount: %s\n", mount.c_str(), umount.c_str());
        m_.reset(new mount_t(mount, umount, pin));
        
        if (prev) prev->set_pin(pin);
    }
    
    std::shared_ptr<mount_t> m_;
};

struct shell_storage_t : storage_t {
    shell_storage_t(const config_t& c, const std::string& pin, std::shared_ptr<storage_t> s = std::shared_ptr<storage_t>())
        : storage_t(shell_driver_c, c, s)
        , timestamp_(0), last_present_(false)
    {
        present_ = c.get<std::string>("present");
        list_ = c.get<std::string>("list");
        read_ = c.get<std::string>("read");
        write_ = c.get<std::string>("write");
        
        set_pin(pin);
    }
    
    virtual void set_pin(const std::string& pin) {
        if (prev) prev->set_pin(pin);
    }
    
    virtual bool present() const {
        
        time_t current = ::time(NULL);
        if (current - timestamp_ < 3) {
            if (last_present_) return true;
        }
        
        last_present_ = (start(present_) == 0);
        st_logf("Shell storage present: %d\n", last_present_);
        timestamp_ = ::time(NULL);
        return last_present_;
    }
      
    virtual std::list<item_t> items() {
        std::list<item_t> result;
        
        std::vector<std::string> files;
        
        try {
            auto data = piped(list_);
            boost::split(files, data, boost::is_any_of("\n"));
        }
        catch (const std::exception& e) {
            timestamp_ = 0;
            if (present()) {
                throw pkcs11_exception_t(CKR_DEVICE_ERROR, std::string("failed to list files: ") + e.what());
            } else {
                throw pkcs11_exception_t(CKR_DEVICE_REMOVED, "device removed");
            }
        }
        
        for(auto file: files) {
            if (file.empty() or file == meta_c) continue;
            
            const item_t item = read(file);
            assert(!item.data.empty());
            result.push_back(item);
        }
        
        return result;
    }
    
    virtual item_t read(const std::string& fn) {
        std::string read = read_;
        boost::replace_all(read, "%FILE%", fn);
        std::string read_meta = read_;
        boost::replace_all(read_meta, "%FILE%", metaname(fn));
        try {
            return item_t {
                fn,
                piped(read),
                parse_meta(piped(read_meta))
            };
        }
        catch(const std::exception& e) {
            timestamp_ = 0;
            if (present()) {
                throw pkcs11_exception_t(CKR_DEVICE_ERROR, std::string("failed to read file: ") + e.what());
            } else {
                throw pkcs11_exception_t(CKR_DEVICE_REMOVED, "device removed");
            }
        }
    }
    
    virtual item_t write(const item_t& item) {
        std::string write_cmd, write_meta_cmd = write_;
        boost::replace_all(write_cmd, "%FILE%", item.filename);
        boost::replace_all(write_meta_cmd, "%FILE%", metaname(item.filename));
        
        try {
            piped(write_cmd, item.data);
            piped(write_meta_cmd, write_meta(item.attributes));
        }
        catch(const std::exception& e) {
            timestamp_ = 0;
            if (present()) {
                throw pkcs11_exception_t(CKR_DEVICE_ERROR, std::string("failed to write file: ") + e.what());
            } else {
                throw pkcs11_exception_t(CKR_DEVICE_REMOVED, "device removed");
            }
        }
        return read(item.filename);
    }
    
    std::string present_;
    std::string list_;
    std::string read_;
    std::string write_;
    
    mutable time_t timestamp_;
    mutable bool last_present_;
};

struct crypt_storage_t : storage_t {
    crypt_storage_t(const config_t& c, const std::string& pin, std::shared_ptr<storage_t> s)
        : storage_t(crypt_driver_c, c, s)
    {
        set_pin(pin);
    }
    
    virtual ~crypt_storage_t() {
    }
    
    virtual void set_pin(const std::string& pin) {
        encrypt_ = config_.get<std::string>("encrypt");        
        decrypt_ = config_.get<std::string>("decrypt");
        
        boost::replace_all(encrypt_, "%PIN%", pin);
        boost::replace_all(decrypt_, "%PIN%", pin);
        
        if (prev) prev->set_pin(pin);
    }
    
    virtual bool present() const {
        return prev->present();
    }
    
    virtual std::list<item_t> items() {
        std::list<item_t> result;
        for(auto item: prev->items()) {
            try {
              const item_t d = decrypt(item);
              if (!d.data.empty()) {
                  result.push_back(d);
              }
            } catch (std::exception& e) {
                st_logf("Can't decrypt file %s: %s\n", item.filename.c_str(), e.what());
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
        try {
            return item_t {
                item.filename,
                piped(decrypt_, item.data),
                item.attributes
            };
        } catch(const std::exception& e) {
            throw pkcs11_exception_t(CKR_DEVICE_ERROR, std::string("failed to decrypt file: ") + e.what());
        }
    }
    
    item_t encrypt(const item_t& item) const {
        try {
            return item_t {
                item.filename,
                piped(encrypt_, item.data),
                item.attributes
            };
        } catch(const std::exception& e) {
            throw pkcs11_exception_t(CKR_DEVICE_ERROR, std::string("failed to decrypt file: ") + e.what());
        }
    }
    
    std::string decrypt_;
    std::string encrypt_;
};


std::shared_ptr<storage_t> storage_t::create(const config_t& config, const std::string& pin)
{
    std::shared_ptr<storage_t> storage;
    BOOST_FOREACH(auto p, config) {
        if (p.second.size() > 0) {
            if (p.second.get<std::string>("driver") == fs_driver_c) {
                storage.reset(new fs_storage_t(p.second, pin, storage));
            }
            else if (p.second.get<std::string>("driver") == fuse_driver_c) {
                storage.reset(new fuse_storage_t(p.second, pin, storage));
            }
            else if (p.second.get<std::string>("driver") == crypt_driver_c) {
                storage.reset(new crypt_storage_t(p.second, pin, storage));
            }
            else if (p.second.get<std::string>("driver") == shell_driver_c) {
                storage.reset(new shell_storage_t(p.second, pin, storage));
            }
        }
    }
    
    return storage;
}


struct to_object_id : std::unary_function<const fs::directory_entry&, CK_OBJECT_HANDLE> {
    CK_OBJECT_HANDLE operator() (const fs::directory_entry& d) const {
        return static_cast<CK_OBJECT_HANDLE>(hash(d.path().filename().c_str()));
    }
    CK_OBJECT_HANDLE operator() (const std::string& filename) const {
        return static_cast<CK_OBJECT_HANDLE>(hash(filename));
    }
private:
    std::hash<std::string> hash;
};

descriptor_t::descriptor_t(const item_t& it)
    : item(it)
{
    if (item.data.empty()) {
        throw std::runtime_error("There is no data in item");
    }
    
    const std::string str(item.data.begin(), item.data.end());
    std::stringstream stream(str);
    
    std::getline(stream, first_line, '\n');
    stream.seekg (0, stream.beg);
    
    id = to_object_id()(item.filename);
    
    st_logf("File: %s hash %lu\n", item.filename.c_str(), id);
    
    void* src = const_cast<char*>(item.data.data());
    file.reset(
        ::fmemopen(src, item.data.size(), "r"),
        ::fclose
    );
    
    if (!file.get()) {
        throw std::runtime_error("Can't memopen data");
    }
};


