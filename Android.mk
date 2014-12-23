LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(call all-java-files-under, src)

LOCAL_AIDL_INCLUDES := packages/apps/SmartCardService/openmobileapi/src/org/simalliance/openmobileapi/service

LOCAL_PACKAGE_NAME := SmartcardService
LOCAL_CERTIFICATE := platform

LOCAL_JAVA_LIBRARIES := framework org.simalliance.openmobileapi

LOCAL_PROGUARD_ENABLED := disabled

include $(BUILD_PACKAGE)

include $(call all-makefiles-under,$(LOCAL_PATH))
