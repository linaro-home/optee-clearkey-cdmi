
AES_CRYPTO_OBJS = aes_crypto.o
AES_CRYPTO_SOURCES = aes_crypto.c clearkey_platform.c
CFG_TEE_TA_LOG_LEVEL ?= 3
AES_CRYPTO_CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) -DCFG_TRACE_LEVEL=3

AES_CRYPTO_CFLAGS += -Wall -I../ta/include -I$(TEEC_EXPORT)/include
AES_CRYPTO_LDADD += -lteec -L$(TEEC_EXPORT)/lib


OPTEE_AES_LIBNAME = aes_crypto
.PHONY: clean all

all:  aes_crypto

.c.o:
	$(CXX) $(CXXFLAGS) $(RPC_INCLUDES) -c $< -o $@

aes_crypto.o:
	@echo Building aes_crypto
	$(CC) $(AES_CRYPTO_CPPFLAGS) $(AES_CRYPTO_CFLAGS) \
		$(AES_CRYPTO_LDADD) $(AES_CRYPTO_LDADD) -o $@ -c $(AES_CRYPTO_SOURCES)  

.cpp.o:
	$(CXX) $(CXXFLAGS) $(CDMI_INCLUDES) -c $< -o $@

aes_crypto: $(AES_CRYPTO_OBJS)
	@echo "Building aes crypto"
	$(AR) rcs lib$(OPTEE_AES_LIBNAME).a $^

#	  $(CC) $(LDADD) -o $@ $<
clean:
	rm  -f *.a *.o
