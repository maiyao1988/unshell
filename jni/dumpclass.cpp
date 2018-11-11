#include <pthread.h>
#include "vm/Common.h"
#include "libdex/DexProto.h"
#include "libdex/DexFile.h"
#include "libdex/DexOptData.h"
#include "libdex/Leb128.h"
#include "libdex/DexClass.h"
#include "libdex/sha1.h"
#include "vm/DvmDex.h"
#include "vm/oo/Object.h"
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>

#include <set>
#include <cstdio>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#define MYLOG(...) \
    __android_log_print(ANDROID_LOG_INFO, "unshell", __VA_ARGS__);
/*

; dvmIsClassInitialized(ClassObject const*)
EXPORT _Z21dvmIsClassInitializedPK11ClassObject

EXPORT bool dvmInitClass(ClassObject* clazz)

; dvmDefineClass(DvmDex *, char const*, Object *)
EXPORT _Z14dvmDefineClassP6DvmDexPKcP6Object

*/

static void *dvmH = dlopen("libdvm.so", RTLD_NOW);

typedef bool (*dvmIsClassInitializedFunc)(ClassObject* clazz);

typedef bool (*dvmInitClassFunc)(ClassObject* clazz);

typedef ClassObject *(*dvmDefineClassFunc)(DvmDex *, char const*, Object *);

typedef void *(*dvmThreadSelfFunc)();

dvmIsClassInitializedFunc dvmIsClassInitialized = (dvmIsClassInitializedFunc)dlsym(dvmH, "_Z21dvmIsClassInitializedPK11ClassObject");

dvmInitClassFunc dvmInitClass = (dvmInitClassFunc)dlsym(dvmH, "dvmInitClass");

dvmDefineClassFunc dvmDefineClass = (dvmDefineClassFunc)dlsym(dvmH, "_Z14dvmDefineClassP6DvmDexPKcP6Object");

dvmThreadSelfFunc dvmThreadSelf = (dvmThreadSelfFunc)dlsym(dvmH, "_Z13dvmThreadSelfv");


static void ReadClassDataHeader(const uint8_t **pData,
                                DexClassDataHeader *pHeader)
{
    pHeader->staticFieldsSize = readUnsignedLeb128(pData);
    pHeader->instanceFieldsSize = readUnsignedLeb128(pData);
    pHeader->directMethodsSize = readUnsignedLeb128(pData);
    pHeader->virtualMethodsSize = readUnsignedLeb128(pData);
}

static void ReadClassDataField(const uint8_t **pData, DexField *pField)
{
    pField->fieldIdx = readUnsignedLeb128(pData);
    pField->accessFlags = readUnsignedLeb128(pData);
}

static void ReadClassDataMethod(const uint8_t **pData, DexMethod *pMethod)
{
    pMethod->methodIdx = readUnsignedLeb128(pData);
    pMethod->accessFlags = readUnsignedLeb128(pData);
    pMethod->codeOff = readUnsignedLeb128(pData);
}

static DexClassData *ReadClassData(const uint8_t **pData)
{

    DexClassDataHeader header;

    if (*pData == NULL)
    {
        return NULL;
    }

    ReadClassDataHeader(pData, &header);

    size_t resultSize = sizeof(DexClassData) + 
    (header.staticFieldsSize * sizeof(DexField)) + 
    (header.instanceFieldsSize * sizeof(DexField)) + 
    (header.directMethodsSize * sizeof(DexMethod)) + 
    (header.virtualMethodsSize * sizeof(DexMethod));

    DexClassData *result = (DexClassData *)malloc(resultSize);

    if (result == NULL)
    {
        return NULL;
    }

    uint8_t *ptr = ((uint8_t *)result) + sizeof(DexClassData);

    result->header = header;

    if (header.staticFieldsSize != 0)
    {
        result->staticFields = (DexField *)ptr;
        ptr += header.staticFieldsSize * sizeof(DexField);
    }
    else
    {
        result->staticFields = NULL;
    }

    if (header.instanceFieldsSize != 0)
    {
        result->instanceFields = (DexField *)ptr;
        ptr += header.instanceFieldsSize * sizeof(DexField);
    }
    else
    {
        result->instanceFields = NULL;
    }

    if (header.directMethodsSize != 0)
    {
        result->directMethods = (DexMethod *)ptr;
        ptr += header.directMethodsSize * sizeof(DexMethod);
    }
    else
    {
        result->directMethods = NULL;
    }

    if (header.virtualMethodsSize != 0)
    {
        result->virtualMethods = (DexMethod *)ptr;
    }
    else
    {
        result->virtualMethods = NULL;
    }

    for (uint32_t i = 0; i < header.staticFieldsSize; i++)
    {
        ReadClassDataField(pData, &result->staticFields[i]);
    }

    for (uint32_t i = 0; i < header.instanceFieldsSize; i++)
    {
        ReadClassDataField(pData, &result->instanceFields[i]);
    }

    for (uint32_t i = 0; i < header.directMethodsSize; i++)
    {
        ReadClassDataMethod(pData, &result->directMethods[i]);
    }

    for (uint32_t i = 0; i < header.virtualMethodsSize; i++)
    {
        ReadClassDataMethod(pData, &result->virtualMethods[i]);
    }

    return result;
}

static void writeLeb128(uint8_t **ptr, uint32_t data)
{
    while (true)
    {
        uint8_t out = data & 0x7f;
        if (out != data)
        {
            *(*ptr)++ = out | 0x80;
            data >>= 7;
        }
        else
        {
            *(*ptr)++ = out;
            break;
        }
    }
}

static uint8_t *EncodeClassData(DexClassData *pData, int &len)
{
    len = 0;

    len += unsignedLeb128Size(pData->header.staticFieldsSize);
    len += unsignedLeb128Size(pData->header.instanceFieldsSize);
    len += unsignedLeb128Size(pData->header.directMethodsSize);
    len += unsignedLeb128Size(pData->header.virtualMethodsSize);

    if (pData->staticFields)
    {
        for (uint32_t i = 0; i < pData->header.staticFieldsSize; i++)
        {
            len += unsignedLeb128Size(pData->staticFields[i].fieldIdx);
            len += unsignedLeb128Size(pData->staticFields[i].accessFlags);
        }
    }

    if (pData->instanceFields)
    {
        for (uint32_t i = 0; i < pData->header.instanceFieldsSize; i++)
        {
            len += unsignedLeb128Size(pData->instanceFields[i].fieldIdx);
            len += unsignedLeb128Size(pData->instanceFields[i].accessFlags);
        }
    }

    if (pData->directMethods)
    {
        for (uint32_t i = 0; i < pData->header.directMethodsSize; i++)
        {
            len += unsignedLeb128Size(pData->directMethods[i].methodIdx);
            len += unsignedLeb128Size(pData->directMethods[i].accessFlags);
            len += unsignedLeb128Size(pData->directMethods[i].codeOff);
        }
    }

    if (pData->virtualMethods)
    {
        for (uint32_t i = 0; i < pData->header.virtualMethodsSize; i++)
        {
            len += unsignedLeb128Size(pData->virtualMethods[i].methodIdx);
            len += unsignedLeb128Size(pData->virtualMethods[i].accessFlags);
            len += unsignedLeb128Size(pData->virtualMethods[i].codeOff);
        }
    }

    uint8_t *store = (uint8_t *)malloc(len);

    if (!store)
    {
        return NULL;
    }

    uint8_t *result = store;

    writeLeb128(&store, pData->header.staticFieldsSize);
    writeLeb128(&store, pData->header.instanceFieldsSize);
    writeLeb128(&store, pData->header.directMethodsSize);
    writeLeb128(&store, pData->header.virtualMethodsSize);

    if (pData->staticFields)
    {
        for (uint32_t i = 0; i < pData->header.staticFieldsSize; i++)
        {
            writeLeb128(&store, pData->staticFields[i].fieldIdx);
            writeLeb128(&store, pData->staticFields[i].accessFlags);
        }
    }

    if (pData->instanceFields)
    {
        for (uint32_t i = 0; i < pData->header.instanceFieldsSize; i++)
        {
            writeLeb128(&store, pData->instanceFields[i].fieldIdx);
            writeLeb128(&store, pData->instanceFields[i].accessFlags);
        }
    }

    if (pData->directMethods)
    {
        for (uint32_t i = 0; i < pData->header.directMethodsSize; i++)
        {
            writeLeb128(&store, pData->directMethods[i].methodIdx);
            writeLeb128(&store, pData->directMethods[i].accessFlags);
            writeLeb128(&store, pData->directMethods[i].codeOff);
        }
    }

    if (pData->virtualMethods)
    {
        for (uint32_t i = 0; i < pData->header.virtualMethodsSize; i++)
        {
            writeLeb128(&store, pData->virtualMethods[i].methodIdx);
            writeLeb128(&store, pData->virtualMethods[i].accessFlags);
            writeLeb128(&store, pData->virtualMethods[i].codeOff);
        }
    }

    return result;
}

static uint8_t *codeitem_end(const u1 **pData)
{
    uint32_t num_of_list = readUnsignedLeb128(pData);
    for (; num_of_list > 0; num_of_list--)
    {
        int32_t num_of_handlers = readSignedLeb128(pData);
        int num = num_of_handlers;
        if (num_of_handlers <= 0)
        {
            num = -num_of_handlers;
        }
        for (; num > 0; num--)
        {
            readUnsignedLeb128(pData);
            readUnsignedLeb128(pData);
        }
        if (num_of_handlers <= 0)
        {
            readUnsignedLeb128(pData);
        }
    }
    return (uint8_t *)(*pData);
}

static void writeExceptClassDef(const char *outDir, DvmDex *pDvmDex) {

    DexFile *pDexFile=pDvmDex->pDexFile;
    MemMapping *mem=&pDvmDex->memMap;
    MYLOG("In %s mem_addr:%p, mem_len:%d", __FUNCTION__, mem->addr, mem->length);

    char temp[255] = {0};
    sprintf(temp, "%s/part1", outDir);
    FILE *fpDef = fopen(temp, "wb");
    const u1 *mapBase = (const u1*)mem->addr;
    const u1 *classDefBase = pDexFile->baseAddr+pDexFile->pHeader->classDefsOff;
    MYLOG("%p %p %d %d", pDexFile, pDexFile->baseAddr, pDexFile->pHeader->classDefsOff, mem->length);
    int length=(int)(classDefBase-mapBase);
    MYLOG("length %d", length);
    fwrite(mapBase,1,length,fpDef);
    MYLOG("after write %s length:%d", temp, length);
    fclose(fpDef);

    size_t totalclsDefSize = sizeof(DexClassDef)*pDexFile->pHeader->classDefsSize;
    sprintf(temp, "%s/data", outDir);
    fpDef = fopen(temp, "wb");
    const u1 *addrAfterClassDefs = classDefBase+totalclsDefSize;
    length=int((const u1*)mem->addr+mem->length-addrAfterClassDefs);
    fwrite(addrAfterClassDefs,1,length,fpDef);
    MYLOG("after write %s length:%d", temp, length);
    fclose(fpDef);
}

static void appenFileTo(const char *path, FILE *targetFd) 
{
    MYLOG("func %s %s %p", __FUNCTION__, path, targetFd);
    FILE *f = fopen(path, "rb");
    if (!f)
    {
        MYLOG("func %s open error", __FUNCTION__);
        return;
    }

    char buf[255] = {0};

    size_t r = 0;
    unsigned len = 0;
    while (1)
    {
        r = fread(buf, 1, sizeof(buf), f);
        if (!r)
            break;
        len += fwrite(buf, 1, r, targetFd);
    }
    fflush(targetFd);
    fclose(f);

    MYLOG("end func %s, appen %d", __FUNCTION__, len);
}

static void dexComputeSHA1Digest(const unsigned char* data, size_t length,
    unsigned char digest[])
{
    SHA1_CTX context;
    SHA1Init(&context);
    SHA1Update(&context, data, length);
    SHA1Final(digest, &context);
}

static void fixDex(const char *dexPath)
{
    int fd = open(dexPath, O_RDWR);
    struct stat st = {0};
    fstat(fd,&st);
    unsigned len = st.st_size;
    const u1 *addr = (const u1*)mmap(NULL,len,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    MYLOG("fixDex mmap base %p, len=%u", addr, len);
    DexFile *dex = dexFileParse(addr, len, kDexParseContinueOnError);
    ((DexHeader*)(dex->pHeader))->fileSize = len;

    const u1 *dataPtrDex = addr;
    int lengthNoOpt = len;
    if (dex->pOptHeader)
    {
        u4 oCheckSum = dex->pOptHeader->checksum;
        u4 optChecksum = dexComputeOptChecksum(dex->pOptHeader);
        MYLOG("regen dex old checksum =0x%08x, new opt checksum = 0x%08x", oCheckSum, optChecksum);
        ((DexOptHeader*)(dex->pOptHeader))->checksum = optChecksum;
        dataPtrDex += dex->pOptHeader->dexOffset;
        lengthNoOpt -= dex->pOptHeader->dexOffset;
    }
    if (dex->pHeader)
    {
        //fix dex checksum
        u4 oCheckSum = dex->pHeader->checksum;
        u4 checksum = dexComputeChecksum(dex->pHeader);
        MYLOG("regen dex oldChecksum = 0x%08x, checksum = 0x%08x, checksum ptr %p", oCheckSum, checksum, &(dex->pHeader->checksum));
        ((DexHeader*)(dex->pHeader))->checksum = checksum;

        //fix signature
        unsigned char sha1Digest[kSHA1DigestLen];
        const int nonSum = sizeof(dex->pHeader->magic) + sizeof(dex->pHeader->checksum) +
                            kSHA1DigestLen;
        
        dexComputeSHA1Digest(dataPtrDex + nonSum, lengthNoOpt - nonSum, sha1Digest);

        memcpy(((DexHeader*)(dex->pHeader))->signature, sha1Digest, kSHA1DigestLen);
    }

    msync((void*)addr, len, MS_SYNC);
    munmap((void*)addr, len);
    close(fd);
    dexFileFree(dex);
}

static bool fixClassDataMethod(DexMethod *methodsToFix, Method *actualMethods, size_t numMethods, DexFile *pDexFile, int dataStart, int dataEnd, FILE *fpExtra, uint32_t &total_pointer)
{
    const uint32_t mask = 0x3ffff;
    bool need_extra = false;
    char desp[255]={0};
    if (methodsToFix)
    {
        for (uint32_t i = 0; i < numMethods; i++)
        {
            Method *actualMethod = &(actualMethods[i]);
            uint32_t realAc = (actualMethod->accessFlags) & mask;

            sprintf(desp, "%s->%s", actualMethod->clazz->descriptor, actualMethod->name);
            if (!actualMethod->insns || realAc & ACC_NATIVE)
            {
                if (methodsToFix[i].codeOff)
                {
                    //真实函数是native，但是待修复函数却有codeoff，休要修复
                    need_extra = true;
                    methodsToFix[i].accessFlags = realAc;
                    methodsToFix[i].codeOff = 0;
                }
                continue;
            }

            u4 realCodeOff = u4((const u1 *)actualMethod->insns - 16 - pDexFile->baseAddr);

            if (realAc != methodsToFix[i].accessFlags)
            {
                //真实函数与待修复函数accessFlags不一致的，休要修复
                MYLOG("[%s] accessFlag not equal, expected:0x%08x, actual:0x%08x", desp, methodsToFix[i].accessFlags, realAc);
                need_extra = true;
                methodsToFix[i].accessFlags = realAc;
            }

            if (realCodeOff != methodsToFix[i].codeOff && ((realCodeOff >= dataStart && realCodeOff <= dataEnd) || realCodeOff == 0))
            {
                //code off不一致，且codeoff在map范围内, 直接将真实codeoff复制过去即可
                MYLOG("[%s] codeoff not equal to actual in map methodToFix_codeoff:0x%08x,real_codeoff:0x%08x,dataStart:0x%08x, dataEnd:0x%08x", 
                    desp, methodsToFix[i].codeOff, realCodeOff, dataStart, dataEnd);
                need_extra = true;
                methodsToFix[i].codeOff = realCodeOff;
            }

            if ((realCodeOff < dataStart || realCodeOff > dataEnd) && realCodeOff != 0)
            {
                //真实codeoff超出data范围的，需要修复
                MYLOG("[%s] real_codeoff out of range real_codeoff:0x%08x,dataStart:0x%08x,dataEnd:0x%08x", 
                    desp, realCodeOff, dataStart, dataEnd);
                need_extra = true;
                methodsToFix[i].codeOff = total_pointer;
                DexCode *code = (DexCode *)((const u1 *)actualMethod->insns - 16);
                uint8_t *item = (uint8_t *)code;
                int code_item_len = 0;
                if (code->triesSize)
                {
                    const u1 *handler_data = dexGetCatchHandlerData(code);
                    const u1 **phandler = (const u1 **)&handler_data;
                    uint8_t *tail = codeitem_end(phandler);
                    code_item_len = (int)(tail - item);
                }
                else
                {
                    code_item_len = 16 + code->insnsSize * 2;
                }

                fwrite(item, 1, code_item_len, fpExtra);
                total_pointer += code_item_len;
                while (total_pointer & 3)
                {
                    //对齐
                    fputc(0, fpExtra);
                    total_pointer++;
                }
                fflush(fpExtra);
            }
        }
    }
    return need_extra;
}

void dumpClass(const char *dumpDir, const char *dexName, DvmDex *pDvmDex, Object *loader)
{
    char tmpDir[255] = {0};
    sprintf(tmpDir, "%s/%s-tmp", dumpDir, dexName);

    mkdir(tmpDir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    writeExceptClassDef(tmpDir, pDvmDex);

    DexFile *pDexFile = pDvmDex->pDexFile;
    MemMapping *mem = &pDvmDex->memMap;

    char path[255] = {0};
    sprintf(path, "%s/classdef", tmpDir);
    FILE *fpDef = fopen(path, "wb");

    sprintf(path, "%s/extra", tmpDir);
    FILE *fpExtra = fopen(path, "wb");

    const char *header = "Landroid";
    unsigned int num_class_defs = pDexFile->pHeader->classDefsSize;
    uint32_t total_pointer = mem->length - uint32_t(pDexFile->baseAddr - (const u1 *)mem->addr);
    uint32_t rec = total_pointer;

    while (total_pointer & 3)
    {
        total_pointer++;
    }

    int inc = total_pointer - rec;
    uint32_t dataStart = pDexFile->pHeader->classDefsOff + sizeof(DexClassDef) * num_class_defs;
    uint32_t dataEnd = (uint32_t)((const u1 *)mem->addr + mem->length - pDexFile->baseAddr);

    void *self = dvmThreadSelf();

    for (size_t i = 0; i < num_class_defs; i++)
    {
        bool need_extra = false;
        const DexClassDef *pClassDef = dexGetClassDef(pDvmDex->pDexFile, i);
        DexClassDef classdef = *pClassDef;
        const char *descriptor = dexGetClassDescriptor(pDvmDex->pDexFile, pClassDef);

        const u1 *data = dexGetClassData(pDexFile, pClassDef);
        DexClassData *pData = ReadClassData(&data);

        if (strncmp(header, descriptor, 8) == 0|| !pClassDef->classDataOff)
        {
            classdef.classDataOff = 0;
            classdef.annotationsOff = 0;
        }
        else 
        {
            ClassObject *clazz = dvmDefineClass(pDvmDex, descriptor, loader);

            char *ptr = (char*)self;

            //clear exception
            //MYLOG("get exception 0x%08x", *(unsigned*)(ptr+68));

            //equal to self->exception=0;
            *(unsigned*)(ptr+68) = 0;
            //MYLOG("after set exception");

            if (clazz)
            {
                //MYLOG("GOT IT class: %s", descriptor);
                if (!dvmIsClassInitialized(clazz))
                {
                    /*
                    if (dvmInitClass(clazz))
                    {
                        MYLOG("GOT IT init: %s", descriptor);
                    }
                    */
                }

                if (pClassDef->classDataOff < dataStart || pClassDef->classDataOff > dataEnd)
                {
                    MYLOG("[%s] classdata out of range, classDataoff:0x%08x, dataStart:0x%08x, dataEnd:0x%08x", descriptor, pClassDef->classDataOff, dataStart, dataEnd);
                    need_extra = true;
                }

                if (pData)
                {
                    need_extra = need_extra || fixClassDataMethod(pData->directMethods, clazz->directMethods, pData->header.directMethodsSize, pDexFile, dataStart, dataEnd, fpExtra, total_pointer);
                    need_extra = need_extra || fixClassDataMethod(pData->virtualMethods, clazz->virtualMethods, pData->header.virtualMethodsSize, pDexFile, dataStart, dataEnd, fpExtra, total_pointer);
                }
            }
            else 
            {
                MYLOG("defineclass: %s return null", descriptor);
            }

        }

        if (need_extra && pData)
        {
            MYLOG("[%s] update classData", descriptor);
            int class_data_len = 0;
            uint8_t *out = EncodeClassData(pData, class_data_len);
            if (out)
            {
                classdef.classDataOff = total_pointer;
                fwrite(out, 1, class_data_len, fpExtra);
                fflush(fpExtra);
                total_pointer += class_data_len;
                while (total_pointer & 3)
                {
                    fputc(0, fpExtra);
                    total_pointer++;
                }
                fflush(fpExtra);
                free(out);
                MYLOG("GOT IT classdata written");
            }
        }
        free(pData);

        fwrite(&classdef, sizeof(classdef), 1, fpDef);
        //MYLOG("after write def");
        fflush(fpDef);
    }

    fclose(fpExtra);
    fclose(fpDef);

    MYLOG("after close def");

    char dexPath[255]={0};
    sprintf(dexPath, "%s/%s", dumpDir, dexName);
    FILE *fpDex = fopen(dexPath, "wb");
    MYLOG("fpDex %s %p", path, fpDex);

    sprintf(path, "%s/part1", tmpDir);
    
    appenFileTo(path, fpDex);

    sprintf(path, "%s/classdef", tmpDir);

    appenFileTo(path, fpDex);

    sprintf(path, "%s/data", tmpDir);

    appenFileTo(path, fpDex);

    while (inc > 0)
    {
        fputc(0, fpExtra);
        inc--;
    }
    fflush(fpDex);

    sprintf(path, "%s/extra", tmpDir);

    appenFileTo(path, fpDex);

    int sz = ftell(fpDex);
    fclose(fpDex);
    MYLOG("here write dex %s return %d writed", dexPath, sz);

    fixDex(dexPath);

    MYLOG("dex %s checksum has fix", dexPath);
}
