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
#include "config.h"
#define TAG "unshell"

pthread_mutex_t sMutex;

__attribute__((constructor)) static void init(){
    pthread_mutex_init(&sMutex, 0);
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
void *p=dlopen("/data/local/tmp/librev.so", RTLD_NOW);

void dumpClass(const char *dumpDir, const char *outDexName, DvmDex *pDvmDex, Object *loader);


static void *dumpThread(void *param) {

    Arg *p = (Arg*)param;

    __android_log_print(ANDROID_LOG_FATAL, TAG, "in dumpThread %s %s %p %p", p->dumpDir, p->dexName, p->pDvmDex, p->loader);

    dumpClass(p->dumpDir, p->dexName, p->pDvmDex, p->loader);

    __android_log_print(ANDROID_LOG_FATAL, TAG, "finish dump %s/%s", p->dumpDir, p->dexName);
    return 0;
}

static void createDumpThread(const char *dumpDir, const char *dexName, DvmDex *pDvmDex, Object *loader) {
    //__android_log_print(ANDROID_LOG_FATAL, TAG, "dvmCreateInternalThread %p", dvmCreateInternalThread);
    
    //memory leak but just for dump is ok here
    Arg *param = (Arg*)malloc(sizeof(Arg));
    param->loader=loader;
    param->pDvmDex=pDvmDex;
    strcpy(param->dumpDir, dumpDir);
    strcpy(param->dexName, dexName);

    //dumpThread(param);
    pthread_t t;
    dvmCreateInternalThreadFun dvmCreateInternalThread = (dvmCreateInternalThreadFun)dlsym(dvmH, "_Z23dvmCreateInternalThreadPlPKcPFPvS2_ES2_");
    dvmCreateInternalThread(&t, "ClassDumper", dumpThread, (void*)param);
    //__android_log_print(ANDROID_LOG_FATAL, TAG, "pthread_create return %d", r);          
}

using namespace std;
static set<void*> s_addrHasDump; 
extern "C" void defineClassNativeCb(const char *fileName, DvmDex *pDvmDex, Object *loader) {
    static const Config &cfg = get_config();
    if (!cfg.sUseDexDump) {
        return;
    }
    
    //const char *pkgName = "cn.missfresh.application";
    const char *pkgName = cfg.sPkgName;
    const char *path = "/proc/self/cmdline";
    char buf[300] = {0};
    FILE *f = fopen(path, "rb");
    fread(buf, 1, sizeof(buf), f);
    fclose(f);
    //__android_log_print(ANDROID_LOG_FATAL, TAG, "cmdline %s", buf);
    if (pkgName[0] == 0 || strstr(buf, pkgName)==0) {
        //__android_log_print(ANDROID_LOG_FATAL, TAG, "%s not the target pkgName", pkgName);
        return;
    }
    
    //__android_log_print(ANDROID_LOG_FATAL, TAG, "find target pkgName %s, pid=%u", pkgName, getpid());
    const MemMapping &memMap = pDvmDex->memMap; 
    pthread_mutex_lock(&sMutex);
    set<void*>::iterator it = s_addrHasDump.find(memMap.addr);
    if (it != s_addrHasDump.end()) {
        //__android_log_print(ANDROID_LOG_FATAL, TAG, "%p has dumped", memMap.addr);
        pthread_mutex_unlock(&sMutex);
        return;
    }
    s_addrHasDump.insert(memMap.addr);
    pthread_mutex_unlock(&sMutex);
    //begin dump

    umask(0);
    char outputDir[255] = {0};
    sprintf(outputDir, "%s/%s_dexes_%d", cfg.hackDir, pkgName, getpid());
    mkdir(outputDir, 0777);

    char dexName[256] = {0};
    size_t hasDump = s_addrHasDump.size();
    sprintf(dexName, "classes_%u.dex", hasDump);
    
    __android_log_print(ANDROID_LOG_FATAL, TAG, "begin dump pkgName %s, base=%p, pid=%u,dexName=%s", pkgName, memMap.addr, getpid(), dexName);
    
    char ijiamiLIb[255] = {0};
    sprintf(ijiamiLIb, "/data/data/%s/files/libexec.so", pkgName);
    /*
    if (strstr(dexName, "classes_8.dex") == 0)
        return;
    */
    
    FILE *fijiami = fopen(ijiamiLIb, "r");
    if (fijiami) {
        __android_log_print(ANDROID_LOG_FATAL, TAG, "find ijiami libexec.so, use direct dump");
        //爱加密的方案无法hook了dvmCreateInternalThread,无法调用该函数，一调用就崩溃，所以只能直接主线程dump
        //另外爱加密hook了__android_log_buf_write,只能打出ERROR以上的日志，所以为了简单调试，全部日志使用Fatal
        fclose(fijiami);
        dumpClass(outputDir, dexName, pDvmDex, loader);
    }
    else {
        __android_log_print(ANDROID_LOG_FATAL, TAG, "use internal thread dump");
        createDumpThread(outputDir, dexName, pDvmDex, loader);
    }

/*
    __android_log_print(ANDROID_LOG_FATAL, TAG, "dumping to %s", outputPath);
    __android_log_print(ANDROID_LOG_FATAL, TAG, "hello %s addr %p len %d baseAddr %p baseLen %d", fileName, memMap.addr, memMap.length, memMap.baseAddr, memMap.baseLength);
    FILE *fdex = fopen(outputPath, "w");
    if (!fdex) {
        __android_log_print(ANDROID_LOG_FATAL, TAG, "can not open %s", outputPath);
        return;
    }
    fwrite(memMap.addr, 1, memMap.length, fdex);
    __android_log_print(ANDROID_LOG_FATAL, TAG, "file has writed ok");
    fclose(fdex);
    */

}
