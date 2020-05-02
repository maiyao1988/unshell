


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

static DexStringCache scache;

__attribute__((constructor)) static void init(){
    dexStringCacheInit(&scache);
}

extern "C" void invokeMethodCb(const Method* methodToCall) {
    int uid = getuid();
    static const Config &cfg = get_config();
    if (cfg.smethodlogUid == uid) {
        const char *desc = dexProtoGetMethodDescriptor(&methodToCall->prototype, &scache);
        __android_log_print(ANDROID_LOG_ERROR, "method-dumps", "%s->%s%s", methodToCall->clazz->descriptor, methodToCall->name, desc);
    }
}
