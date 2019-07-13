LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := unpack
LOCAL_LDLIBS := \
    -llog \

LOCAL_SRC_FILES := \
	unpack.cpp \
	dumpclass.cpp \
	config.cpp \
	methodlog.cpp \
	libdex/DexCatch.cpp \
	libdex/DexClass.cpp \
	libdex/DexDataMap.cpp \
	libdex/DexDebugInfo.cpp \
	libdex/DexFile.cpp \
	libdex/DexInlines.cpp \
	libdex/DexOptData.cpp \
	libdex/DexOpcodes.cpp \
	libdex/DexProto.cpp \
	libdex/DexUtf.cpp \
	libdex/DexSwapVerify.cpp \
	libdex/InstrUtils.cpp \
	libdex/Leb128.cpp \
	libdex/sha1.cpp \
	libdex/SysUtil.cpp \
	libdex/ZipArchive.cpp \
	zlib/adler32.c \
	zlib/compress.c \
	zlib/crc32.c \
	zlib/deflate.c \
	zlib/gzclose.c \
	zlib/gzlib.c \
	zlib/gzread.c \
	zlib/gzwrite.c \
	zlib/infback.c \
	zlib/inflate.c \
	zlib/inftrees.c \
	zlib/inffast.c \
	zlib/trees.c \
	zlib/uncompr.c \
	zlib/zutil.c

dex_include_files := \
	dalvik \
	zlib \
	safe-iop/include

include $(BUILD_SHARED_LIBRARY)