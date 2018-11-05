#include <pthread.h>
#include "vm/Common.h"
#include "libdex/DexProto.h"
#include "libdex/DexFile.h"
#include "vm/DvmDex.h"
#include "vm/oo/Object.h"
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>

#include <set>
#include <cstdio>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#define TAG "unshell"


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
}param;

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
    
    Arg param;

    param.loader=loader;
    param.pDvmDex=pDvmDex;
    strcpy(param.dumpDir, dumpDir);
    strcpy(param.dexName, dexName);

    pthread_t dumpthread;
    dvmCreateInternalThread(&dumpthread, "ClassDumper", dumpThread, (void*)&param);                             

}

using namespace std;
static set<void*> s_addrHasDump; 
extern "C" void defineClassNativeCb(const char *fileName, DvmDex *pDvmDex, Object *loader) {
    //const char *pkgName = "cn.missfresh.application";
    const char *pkgName = "com.pmp.ppmoney";
    const char *path = "/proc/self/cmdline";
    char buf[300] = {0};
    FILE *f = fopen(path, "rb");
    fread(buf, 1, sizeof(buf), f);
    fclose(f);
    //__android_log_print(ANDROID_LOG_INFO, TAG, "cmdline %s", buf);
    if (strstr(buf, pkgName)==0) {
        //__android_log_print(ANDROID_LOG_INFO, TAG, "%s not the target pkgName", buf);
        return;
    }
    
    //__android_log_print(ANDROID_LOG_INFO, TAG, "find target pkgName %s, pid=%u", pkgName, getpid());
    const MemMapping &memMap = pDvmDex->memMap; 
    set<void*>::iterator it = s_addrHasDump.find(memMap.addr);
    if (it != s_addrHasDump.end()) {
        //__android_log_print(ANDROID_LOG_INFO, TAG, "%p has dumped", memMap.addr);
        return;
    }
    s_addrHasDump.insert(memMap.addr);

    //begin dump

    char outputDir[255] = {0};
    sprintf(outputDir, "/data/local/tmp_%d", getpid());
    mkdir(outputDir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    char outputPath[256] = {0};
    sprintf(outputPath, "%s/%s_%u.dex", outputDir, pkgName, s_addrHasDump.size());
    createDumpThread(outputDir, outputPath, pDvmDex, loader);

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
