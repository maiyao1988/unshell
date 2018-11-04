#include <pthread.h>
#include "vm/Common.h"
#include "libdex/DexProto.h"
#include "libdex/DexFile.h"
#include "libdex/Leb128.h"
#include "libdex/DexClass.h"
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

dvmIsClassInitializedFunc dvmIsClassInitialized = (dvmIsClassInitializedFunc)dlsym(dvmH, "_Z21dvmIsClassInitializedPK11ClassObject");

dvmInitClassFunc dvmInitClass = (dvmInitClassFunc)dlsym(dvmH, "dvmInitClass");

dvmDefineClassFunc dvmDefineClass = (dvmDefineClassFunc)dlsym(dvmH, "_Z14dvmDefineClassP6DvmDexPKcP6Object");


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

    size_t resultSize = sizeof(DexClassData) + (header.staticFieldsSize * sizeof(DexField)) + (header.instanceFieldsSize * sizeof(DexField)) + (header.directMethodsSize * sizeof(DexMethod)) + (header.virtualMethodsSize * sizeof(DexMethod));

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

    free(pData);
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

static void writeExceptClassDef(const char *dumpDir, DvmDex *pDvmDex) {

    DexFile* pDexFile=pDvmDex->pDexFile;
    MemMapping * mem=&pDvmDex->memMap;

    char temp[255] = {0};
    sprintf(temp, "%s/part1", dumpDir);
    FILE *fpDef = fopen(temp, "wb");
    const u1 *addr = (const u1*)mem->addr;
    int length=int(pDexFile->baseAddr+pDexFile->pHeader->classDefsOff-addr);
    fwrite(addr,1,length,fpDef);
    fclose(fpDef);


    sprintf(temp, "%s/data", dumpDir);
    fpDef = fopen(temp, "wb");
    addr = pDexFile->baseAddr+pDexFile->pHeader->classDefsOff+sizeof(DexClassDef)*pDexFile->pHeader->classDefsSize;
    length=int((const u1*)mem->addr+mem->length-addr);
    fwrite(addr,1,length,fpDef);
    fclose(fpDef);
}

static void appenFileTo(const char *path, FILE *targetFd) 
{
    int fd = open(path, O_RDONLY, 0666);
    if (fd == -1)
    {
        return;
    }

    struct stat st = {0};
    int r = fstat(fd, &st);

    int len = st.st_size;
    char *addr = (char *)mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    fwrite(addr, 1, len, targetFd);
    fflush(targetFd);
    munmap(addr, len);
    close(fd);
}

void dumpClass(const char *dumpDir, const char *outDexName, DvmDex *pDvmDex, Object *loader)
{
    writeExceptClassDef(dumpDir, pDvmDex);

    DexFile *pDexFile = pDvmDex->pDexFile;
    MemMapping *mem = &pDvmDex->memMap;

    char path[255] = {0};
    sprintf(path, "%s/classdef", dumpDir);
    FILE *fpDef = fopen(path, "wb");

    sprintf(path, "%s/extra", dumpDir);
    FILE *fpExtra = fopen(path, "wb");

    uint32_t mask = 0x3ffff;
    char padding = 0;
    const char *header = "Landroid";
    unsigned int num_class_defs = pDexFile->pHeader->classDefsSize;
    uint32_t total_pointer = mem->length - uint32_t(pDexFile->baseAddr - (const u1 *)mem->addr);
    uint32_t rec = total_pointer;

    while (total_pointer & 3)
    {
        total_pointer++;
    }

    int inc = total_pointer - rec;
    uint32_t start = pDexFile->pHeader->classDefsOff + sizeof(DexClassDef) * num_class_defs;
    uint32_t end = (uint32_t)((const u1 *)mem->addr + mem->length - pDexFile->baseAddr);

    for (size_t i = 0; i < num_class_defs; i++)
    {
        bool need_extra = false;
        ClassObject *clazz = NULL;
        const u1 *data = NULL;
        DexClassData *pData = NULL;
        bool pass = false;
        const DexClassDef *pClassDef = dexGetClassDef(pDvmDex->pDexFile, i);
        const char *descriptor = dexGetClassDescriptor(pDvmDex->pDexFile, pClassDef);

        if (!strncmp(header, descriptor, 8) || !pClassDef->classDataOff)
        {
            pass = true;
            goto classdef;
        }

        clazz = dvmDefineClass(pDvmDex, descriptor, loader);

        if (!clazz)
        {
            continue;
        }

        ALOGI("GOT IT class: %s", descriptor);

        if (!dvmIsClassInitialized(clazz))
        {
            if (dvmInitClass(clazz))
            {
                ALOGI("GOT IT init: %s", descriptor);
            }
        }

        if (pClassDef->classDataOff < start || pClassDef->classDataOff > end)
        {
            need_extra = true;
        }

        data = dexGetClassData(pDexFile, pClassDef);
        pData = ReadClassData(&data);

        if (!pData)
        {
            continue;
        }

        if (pData->directMethods)
        {
            for (uint32_t i = 0; i < pData->header.directMethodsSize; i++)
            {
                Method *method = &(clazz->directMethods[i]);
                uint32_t ac = (method->accessFlags) & mask;

                ALOGI("GOT IT direct method name %s.%s", descriptor, method->name);

                if (!method->insns || ac & ACC_NATIVE)
                {
                    if (pData->directMethods[i].codeOff)
                    {
                        need_extra = true;
                        pData->directMethods[i].accessFlags = ac;
                        pData->directMethods[i].codeOff = 0;
                    }
                    continue;
                }

                u4 codeitem_off = u4((const u1 *)method->insns - 16 - pDexFile->baseAddr);

                if (ac != pData->directMethods[i].accessFlags)
                {
                    ALOGI("GOT IT method ac");
                    need_extra = true;
                    pData->directMethods[i].accessFlags = ac;
                }

                if (codeitem_off != pData->directMethods[i].codeOff && ((codeitem_off >= start && codeitem_off <= end) || codeitem_off == 0))
                {
                    ALOGI("GOT IT method code");
                    need_extra = true;
                    pData->directMethods[i].codeOff = codeitem_off;
                }

                if ((codeitem_off < start || codeitem_off > end) && codeitem_off != 0)
                {
                    need_extra = true;
                    pData->directMethods[i].codeOff = total_pointer;
                    DexCode *code = (DexCode *)((const u1 *)method->insns - 16);
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

                    ALOGI("GOT IT method code changed");

                    fwrite(item, 1, code_item_len, fpExtra);
                    fflush(fpExtra);
                    total_pointer += code_item_len;
                    while (total_pointer & 3)
                    {
                        fwrite(&padding, 1, 1, fpExtra);
                        fflush(fpExtra);
                        total_pointer++;
                    }
                }
            }
        }

        if (pData->virtualMethods)
        {
            for (uint32_t i = 0; i < pData->header.virtualMethodsSize; i++)
            {
                Method *method = &(clazz->virtualMethods[i]);
                uint32_t ac = (method->accessFlags) & mask;

                ALOGI("GOT IT virtual method name %s.%s", descriptor, method->name);

                if (!method->insns || ac & ACC_NATIVE)
                {
                    if (pData->virtualMethods[i].codeOff)
                    {
                        need_extra = true;
                        pData->virtualMethods[i].accessFlags = ac;
                        pData->virtualMethods[i].codeOff = 0;
                    }
                    continue;
                }

                u4 codeitem_off = u4((const u1 *)method->insns - 16 - pDexFile->baseAddr);

                if (ac != pData->virtualMethods[i].accessFlags)
                {
                    ALOGI("GOT IT method ac");
                    need_extra = true;
                    pData->virtualMethods[i].accessFlags = ac;
                }

                if (codeitem_off != pData->virtualMethods[i].codeOff && ((codeitem_off >= start && codeitem_off <= end) || codeitem_off == 0))
                {
                    ALOGI("GOT IT method code");
                    need_extra = true;
                    pData->virtualMethods[i].codeOff = codeitem_off;
                }

                if ((codeitem_off < start || codeitem_off > end) && codeitem_off != 0)
                {
                    need_extra = true;
                    pData->virtualMethods[i].codeOff = total_pointer;
                    DexCode *code = (DexCode *)((const u1 *)method->insns - 16);
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

                    ALOGI("GOT IT method code changed");

                    fwrite(item, 1, code_item_len, fpExtra);
                    fflush(fpExtra);
                    total_pointer += code_item_len;
                    while (total_pointer & 3)
                    {
                        fwrite(&padding, 1, 1, fpExtra);
                        fflush(fpExtra);
                        total_pointer++;
                    }
                }
            }
        }

    classdef:
        DexClassDef temp = *pClassDef;
        uint8_t *p = (uint8_t *)&temp;

        if (need_extra)
        {
            ALOGI("GOT IT classdata before");
            int class_data_len = 0;
            uint8_t *out = EncodeClassData(pData, class_data_len);
            if (!out)
            {
                continue;
            }
            temp.classDataOff = total_pointer;
            fwrite(out, 1, class_data_len, fpExtra);
            fflush(fpExtra);
            total_pointer += class_data_len;
            while (total_pointer & 3)
            {
                fwrite(&padding, 1, 1, fpExtra);
                fflush(fpExtra);
                total_pointer++;
            }
            free(out);
            ALOGI("GOT IT classdata written");
        }
        else
        {
            if (pData)
            {
                free(pData);
            }
        }

        if (pass)
        {
            temp.classDataOff = 0;
            temp.annotationsOff = 0;
        }

        ALOGI("GOT IT classdef");
        fwrite(p, sizeof(DexClassDef), 1, fpDef);
        fflush(fpDef);
    }

    fclose(fpExtra);
    fclose(fpDef);

    sprintf(path, "%s/%s", dumpDir, outDexName);
    FILE *fpDex = fopen(path, "wb");
    rewind(fpDex);

    sprintf(path, "%s/part1", dumpDir);
    
    appenFileTo(path, fpDex);

    sprintf(path, "%s/classdef", dumpDir);

    appenFileTo(path, fpDex);

    sprintf(path, "%s/data", dumpDir);

    appenFileTo(path, fpDex);

    while (inc > 0)
    {
        fwrite(&padding, 1, 1, fpDex);
        fflush(fpDex);
        inc--;
    }

    sprintf(path, "%s/extra", dumpDir);

    appenFileTo(path, fpDex);

    fclose(fpDex);

    return;
}
