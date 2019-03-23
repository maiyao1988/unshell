#include <pthread.h>
#include "vm/Common.h"
#include "libdex/DexProto.h"
#include "libdex/DexFile.h"
#include "libdex/DexOptData.h"
#include "vm/DvmDex.h"
#include "vm/oo/Object.h"
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>

#include <set>
#include <cstdio>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#define TAG "unshell"

pthread_mutex_t sMutex;
bool sUseDexDump = false;
char sPkgName[256] = "";

static const char *trimCpy(char *dest, const char *src) {
    char *q = dest;
    const char *p = src;
    while(*p) {
        if (!isspace(*p)) {
            *q++ = *p++;
        }
        else {
            p++;
        }
    }
    return dest;
}

__attribute__((constructor)) static void init(){
    pthread_mutex_init(&sMutex, 0);
    const char *cfgPath = "/data/local/tmp/cfg.txt";
    FILE *f = fopen(cfgPath, "rb");
    if (!f) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "cfg not found skip");
        return;
    }
    char buf[500];
    while (fgets(buf, sizeof(buf), f) != NULL) {
        char *p = strchr(buf, '=');
        if (p) {
            *p = 0;
            const char *key = buf;
            const char *val = p + 1;
            __android_log_print(ANDROID_LOG_INFO, TAG, "key=%s, val=%s", key, val);
            if (strcmp(key, "useDexDump") == 0) {
                sUseDexDump = (*val) != '0';
                __android_log_print(ANDROID_LOG_INFO, TAG, "use dex %d", sUseDexDump);
            }
            if (strcmp(key, "pkgName") == 0) {
                trimCpy(sPkgName, val);
                __android_log_print(ANDROID_LOG_INFO, TAG, "pkgName = %s", sPkgName);
            }
        }
    }
    fclose(f);
}


typedef bool (*dvmCreateInternalThreadFun)(pthread_t *, const char *, void *(*)(void *), void *);
/*

; dvmIsClassInitialized(ClassObject const*)
EXPORT _Z21dvmIsClassInitializedPK11ClassObject

; dvmDefineClass(DvmDex *, char const*, Object *)
EXPORT _Z14dvmDefineClassP6DvmDexPKcP6Object

; _DWORD __fastcall dvmCreateInternalThread(int *, const char *, void *(__cdecl *)(void *), void *)
EXPORT _Z23dvmCreateInternalThreadPlPKcPFPvS2_ES2_

EXPORT bool dvmInitClass(ClassObject* clazz)

*/
struct Arg{
    DvmDex *pDvmDex;
    Object *loader;

    char dumpDir[255];
    char dexName[100];
};

void *dvmH = dlopen("libdvm.so", RTLD_NOW);

void dumpClass(const char *dumpDir, const char *outDexName, DvmDex *pDvmDex, Object *loader);

static void *dumpThread(void *param) {
    Arg *p = (Arg*)param;

    __android_log_print(ANDROID_LOG_INFO, TAG, "in dumpThread %s %s %p %p", p->dumpDir, p->dexName, p->pDvmDex, p->loader);

    dumpClass(p->dumpDir, p->dexName, p->pDvmDex, p->loader);
    return 0;
}

static void createDumpThread(const char *dumpDir, const char *dexName, DvmDex *pDvmDex, Object *loader) {
    dvmCreateInternalThreadFun dvmCreateInternalThread = (dvmCreateInternalThreadFun)dlsym(dvmH, "_Z23dvmCreateInternalThreadPlPKcPFPvS2_ES2_");
    
    __android_log_print(ANDROID_LOG_INFO, TAG, "dvmCreateInternalThread %p", dvmCreateInternalThread);
    
    //memory leak but just for dump is ok here
    Arg *param = (Arg*)malloc(sizeof(Arg));
    param->loader=loader;
    param->pDvmDex=pDvmDex;
    strcpy(param->dumpDir, dumpDir);
    strcpy(param->dexName, dexName);

    pthread_t dumpthread;
    dvmCreateInternalThread(&dumpthread, "ClassDumper", dumpThread, (void*)param);                             

}

using namespace std;
static set<void*> s_addrHasDump; 
extern "C" void defineClassNativeCb(const char *fileName, DvmDex *pDvmDex, Object *loader) {
    if (!sUseDexDump) {
        return;
    }
    
    //const char *pkgName = "cn.missfresh.application";
    const char *pkgName = sPkgName;
    const char *path = "/proc/self/cmdline";
    char buf[300] = {0};
    FILE *f = fopen(path, "rb");
    fread(buf, 1, sizeof(buf), f);
    fclose(f);
    //__android_log_print(ANDROID_LOG_INFO, TAG, "cmdline %s", buf);
    if (strstr(buf, pkgName)==0) {
        //__android_log_print(ANDROID_LOG_INFO, TAG, "%s not the target pkgName", pkgName);
        return;
    }
    
    __android_log_print(ANDROID_LOG_INFO, TAG, "find target pkgName %s, pid=%u", pkgName, getpid());
    const MemMapping &memMap = pDvmDex->memMap; 
    pthread_mutex_lock(&sMutex);
    set<void*>::iterator it = s_addrHasDump.find(memMap.addr);
    if (it != s_addrHasDump.end()) {
        //__android_log_print(ANDROID_LOG_INFO, TAG, "%p has dumped", memMap.addr);
        pthread_mutex_unlock(&sMutex);
        return;
    }
    s_addrHasDump.insert(memMap.addr);
    pthread_mutex_unlock(&sMutex);
    //begin dump

    char outputDir[255] = {0};
    sprintf(outputDir, "/data/local/tmp/dexes_%d", getpid());
    mkdir(outputDir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    char dexName[256] = {0};
    sprintf(dexName, "%s_%u.dex", pkgName, s_addrHasDump.size());
    createDumpThread(outputDir, dexName, pDvmDex, loader);

/*
    __android_log_print(ANDROID_LOG_INFO, TAG, "dumping to %s", outputPath);
    __android_log_print(ANDROID_LOG_INFO, TAG, "hello %s addr %p len %d baseAddr %p baseLen %d", fileName, memMap.addr, memMap.length, memMap.baseAddr, memMap.baseLength);
    FILE *fdex = fopen(outputPath, "w");
    if (!fdex) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "can not open %s", outputPath);
        return;
    }
    fwrite(memMap.addr, 1, memMap.length, fdex);
    __android_log_print(ANDROID_LOG_INFO, TAG, "file has writed ok");
    fclose(fdex);
    */

}
