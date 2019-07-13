

#ifndef MY_CONFIG
#define MY_CONFIG
struct Config {
    int smethodlogUid;
    bool sUseDexDump;;
    char sPkgName[256];
    char hackDir[256];
};

const Config &get_config();

#endif