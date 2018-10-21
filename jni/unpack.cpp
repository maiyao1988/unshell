#include <pthread.h>
#include "vm/Common.h"
#include "libdex/DexProto.h"
#include "libdex/DexFile.h"
#include "vm/DvmDex.h"
#include "vm/oo/Object.h"
#include <jni.h>
#include <android/log.h>

#define TAG "unshell"
extern "C" void defineClassNativeCb(const char *fileName, DvmDex *pDvmDex, Object *loader) {
    const MemMapping &memMap = pDvmDex->memMap; 
    __android_log_print(ANDROID_LOG_INFO, TAG, "hello %s addr %p len %d baseAddr %p baseLen %d", fileName, memMap.addr, memMap.length, memMap.baseAddr, memMap.baseLength);

}
