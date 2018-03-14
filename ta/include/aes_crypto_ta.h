/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef OPTEE_AES_DECRYPTOR_TA_H
#define OPTEE_AES_DECRYPTOR_TA_H

#define TA_AES_DECRYPTOR_UUID { 0x442ed209, 0xb8e2, 0x405e, \
    { 0x83, 0x84, 0x5c, 0xc7, 0x8c, 0x75, 0x34, 0x28} }

/* The commands implemented in this TA */
enum {
  /*
   * AES CTR127 ENCRYPTION using a Counter IV */
  TA_AES_CTR128_ENCRYPT = 0,
  TA_COPY_SECURE_MEMORY,
};

/*
 * Index of various data structures in TEE payload.
 * Any modification in this enum needs to be synced
 * with AES_CTR128_ENCRYPT_TEE_PARAM_TYPES.
 */
enum {
 PARAM_AES_ENCRYPTED_BUFFER_IDX = 0,
 PARAM_AES_DECRYPTED_BUFFER_IDX,
 PARAM_AES_IV_IDX,
 PARAM_AES_KEY,
};//Max size of this enum is 4, limited by TEEC_PAYLOAD_REF_COUNT

/*
 * Index of various data structures in COPY_SECURE_MEMORY command.
 * Any modification in this enum needs to be synced
 * with COPY_SECURE_MEMORY_PARAM_TYPES
 */
enum {
 PARAM_COPY_SECURE_MEMORY_SOURCE = 0,
 PARAM_COPY_SECURE_MEMORY_DESTINATION
};//Max size of this enum is 4, limited by TEEC_PAYLOAD_REF_COUNT


#define AES_CTR128_ENCRYPT_TEE_PARAM_TYPES TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,\
               TEE_PARAM_TYPE_MEMREF_OUTPUT,\
               TEE_PARAM_TYPE_MEMREF_INPUT,\
               TEE_PARAM_TYPE_MEMREF_INPUT);

#define COPY_SECURE_MEMORY_TEE_PARAM_TYPES TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,\
               TEE_PARAM_TYPE_MEMREF_OUTPUT,\
               TEE_PARAM_TYPE_NONE,\
               TEE_PARAM_TYPE_NONE);


#define IMAGE_END 2
#define AES_KEY_IS_CLEARKEY 4

#endif /* OPTEE_AES_DECRYPTOR_TA_H */
