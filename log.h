
#ifndef ST_LOG_H
#define ST_LOG_H


struct logger_t {
    static logger_t& instance();
    
    logger_t& operator()(const std::string& msg);
    logger_t& operator()(const char* fmt, ...);
    
    struct scopped_t {
        scopped_t();
        ~scopped_t();
    };
    
private:
    void print_tab();
};



#define LOG(msg, ...) logger_t::instance()(msg "\n", ##__VA_ARGS__);
#define LOG_F(msg, ...) logger_t::instance()(__FUNCTION__ msg "\n", ##__VA_ARGS__);

#define LOG_G(msg, ...) logger_t::instance()(msg "\n", ##__VA_ARGS__); logger_t::scopped_t s__;


#endif