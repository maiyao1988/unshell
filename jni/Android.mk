LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := unpack
LOCAL_LDLIBS := \
    -llog \

LOCAL_SRC_FILES := \
	unpack.cpp \

#LOCAL_C_INCLUDES += D:\as_workspace\NDKDemo2\plasmatest\src\debug\jni

include $(BUILD_SHARED_LIBRARY)