#ifndef SOFT_TOKEN_H
#define SOFT_TOKEN_H

#include <string>
#include <memory>

class soft_token_t {
public:
  
    soft_token_t(const std::string& rcfile);
    ~soft_token_t();
    
    bool logged_in() const;
    
    int open_sessions() const {
      return 0;
    }
  
private:
    void each_file(const std::string& path, std::function<void(std::string)> f);
  
    struct Pimpl;
    std::auto_ptr<Pimpl> p_;
};



#endif

