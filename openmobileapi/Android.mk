LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := org.simalliance.openmobileapi.xml
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/permissions
LOCAL_SRC_FILES := $(LOCAL_MODULE)

include $(BUILD_PREBUILT)



include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(call all-java-files-under, src)
LOCAL_SRC_FILES += \
      src/org/simalliance/openmobileapi/service/ISmartcardServiceCallback.aidl \
      src/org/simalliance/openmobileapi/service/ISmartcardServiceReader.aidl \
      src/org/simalliance/openmobileapi/service/ISmartcardServiceChannel.aidl \
      src/org/simalliance/openmobileapi/service/ISmartcardServiceSession.aidl \
      src/org/simalliance/openmobileapi/service/ISmartcardService.aidl

LOCAL_AIDL_INCLUDES := packages/apps/SmartCardService/openmobileapi/src/org/simalliance/openmobileapi/service

LOCAL_MODULE:= org.simalliance.openmobileapi
LOCAL_MODULE_TAGS := optional

include $(BUILD_JAVA_LIBRARY)


# put the classes.jar, with full class files instead of classes.dex inside, into the dist directory
$(call dist-for-goals, droidcore, $(full_classes_jar):org.simalliance.openmobileapi.jar)


