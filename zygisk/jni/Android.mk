LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := zygisk_detach
LOCAL_SRC_FILES := module.cpp parcel.cpp
LOCAL_LDLIBS := -llog -lstdc++
include $(BUILD_SHARED_LIBRARY)