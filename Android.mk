LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(call all-java-files-under, src)
LOCAL_SRC_FILES += \ $(call all-java-files-under, common/src)
LOCAL_SRC_FILES += \ $(call all-Iaidl-files-under, common/src)

LOCAL_AIDL_INCLUDES := $(LOCAL_PATH)/common/src/

LOCAL_PACKAGE_NAME := SmartcardService
LOCAL_CERTIFICATE := platform

LOCAL_PROGUARD_ENABLED := disabled

include $(BUILD_PACKAGE)

include $(call all-makefiles-under,$(LOCAL_PATH))
