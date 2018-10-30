#include <pthread.h>
#include "vm/Common.h"
#include "libdex/DexProto.h"
#include "libdex/DexFile.h"
#include "vm/DvmDex.h"
#include "vm/oo/Object.h"
#include <jni.h>
#include <android/log.h>

#include <set>
#include <cstdio>
#include <unistd.h>
#define TAG "unshell"

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

    const char *outputDir = "/data/local/tmp/";
    char outputPath[256] = {0};
    sprintf(outputPath, "%s/%s_%u_%d.dex", outputDir, pkgName, getpid(), s_addrHasDump.size());

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

}
