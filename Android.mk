################################################################################
# Android optee-hello-world makefile                                           #
################################################################################
LOCAL_PATH := $(call my-dir)

INCLUDE_FOR_BUILD_TA := false
include $(BUILD_OPTEE_MK)
INCLUDE_FOR_BUILD_TA :=

include $(CLEAR_VARS)

CFG_TEEC_PUBLIC_INCLUDE = $(LOCAL_PATH)/../optee_client/public

################################################################################
# Build hello world                                                            #
################################################################################
include $(CLEAR_VARS)
LOCAL_CFLAGS += -DANDROID_BUILD
#-DSDP_PROTOTYPE
LOCAL_CFLAGS += -Wall

LOCAL_SRC_FILES += host/aes_crypto.c host/clearkey_platform.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/ta/include \
		$(CFG_TEEC_PUBLIC_INCLUDE) \

LOCAL_SHARED_LIBRARIES := libteec \
	liblog \
	libion

LOCAL_MODULE := libtee_aes
LOCAL_MODULE_TAGS := optional
#LOCAL_MODULE_TARGET_ARCH := arm aarch64

# Build the 32-bit version.
LOCAL_MULTILIB := both

include $(BUILD_SHARED_LIBRARY)

include $(LOCAL_PATH)/ta/Android.mk
include $(LOCAL_PATH)/../tests/Android.mk

