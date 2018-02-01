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

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <tee_client_api.h>
#include <aes_crypto_ta.h>
#include <stdio.h>
#include <stdlib.h>

#include "aes_crypto.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

#define PR(args...) do { printf(args); fflush(stdout); } while (0)

#define CHECK_INVOKE2(res, orig, fn)              \
  do {                    \
    if (res != TEEC_SUCCESS)            \
      errx(1, "TEEC_InvokeCommand failed with code 0x%x " \
           "origin 0x%x", res, orig);         \
  } while(0)

#define CHECK_INVOKE(res, orig) CHECK_INVOKE2(res, orig, "TEE_InvokeCommand")

#define CHECK(res, fn)                  \
  do {                    \
    if (res != TEEC_SUCCESS)            \
      errx(1, fn " failed with code 0x%x ", res);     \
  } while(0)


/* Globals */

static TEEC_Context ctx;
static TEEC_Session sess;

static TEEC_SharedMemory g_shm;
static TEEC_SharedMemory g_outm;

static TEEC_SharedMemory g_key = {
  .size = CTR_AES_BLOCK_SIZE, /* 16byte key */
  .flags = TEEC_MEM_INPUT,
};

static TEEC_SharedMemory g_iv = {
  .size = CTR_AES_BLOCK_SIZE,
  .flags = TEEC_MEM_INPUT,
};

#define FP(args...) do { fprintf(stderr, args); } while(0)

static void allocate_mem(void)
{
  TEEC_Result res;

  /* Allocate Initialization Vector shared with TEE */
  res = TEEC_AllocateSharedMemory(&ctx, &g_iv);
  CHECK(res, "TEEC_AllocateSharedMemory for IV");

  /* Allocate shared memory for key */
  res = TEEC_AllocateSharedMemory(&ctx, &g_key);
  CHECK(res,  "TEEC_AllocateSharedMemory for key");

}

static void free_mem(void)
{
  PR("Release IV shared memory...\n");
  TEEC_ReleaseSharedMemory(&g_iv);
  PR("Release key shared memory...\n");
  TEEC_ReleaseSharedMemory(&g_key);
}

static uint32_t commit_buffer_tee_aes_ctr128_decrypt(uint32_t sz,  const void* iv,
    uint32_t iv_size,
    const char* key, uint32_t key_size, int flags)
{
  TEEC_Result res;
  TEEC_Operation op;
  uint32_t err_origin;

  assert(key_size == g_key.size);
  assert(iv_size == CTR_AES_IV_SIZE);

  /* Store keys in shared memory */
  memcpy(g_key.buffer, key, key_size);
  memcpy(g_iv.buffer, iv, iv_size);

  op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
           TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE,
           TEEC_MEMREF_WHOLE);

  /* TA input buffer */
  op.params[PARAM_AES_ENCRYPTED_BUFFER_IDX].memref.parent = &g_shm;
  op.params[PARAM_AES_ENCRYPTED_BUFFER_IDX].memref.offset = 0;
  op.params[PARAM_AES_ENCRYPTED_BUFFER_IDX].memref.size = sz;
  /* TA output buffer */
  op.params[PARAM_AES_DECRYPTED_BUFFER_IDX].memref.parent = &g_outm;
  /* TA IV */
  op.params[PARAM_AES_IV_IDX].memref.parent = &g_iv;
  op.params[PARAM_AES_IV_IDX].memref.size = iv_size;
  /* TA Key */
  op.params[PARAM_AES_KEY].memref.parent = &g_key;
  op.params[PARAM_AES_KEY].memref.size =  key_size;

  res = TEEC_InvokeCommand(&sess, TA_AES_CTR128_ENCRYPT, &op,
         &err_origin);
  CHECK_INVOKE(res, err_origin);

  return sz;
}

/* Decrypt buffer
 *
 * Warning: This function is not thread safe!
 * We using only one instance of the shared memory.
 * The OP TEE shared memory is a limited resource and
 * we want to avoid re-allocations.
 * */

int
TEE_AES_ctr128_encrypt(const unsigned char* in_data,
    unsigned char* out_data,
    uint32_t length, const char* key,
    unsigned char iv[CTR_AES_BLOCK_SIZE],
    unsigned char ecount_buf[CTR_AES_BLOCK_SIZE],
    unsigned int *num) {
    TEEC_Result res;

  g_shm.size = length;
  g_shm.buffer = (void *) in_data;
  g_shm.flags = TEEC_MEM_INPUT;

  res = TEEC_RegisterSharedMemory(&ctx, &g_shm);
  CHECK(res, "TEEC_RegisterSharedMemory: g_shm (in buf) failed");

  g_outm.size = length;
  g_outm.buffer = (void *) out_data;
  g_outm.flags = TEEC_MEM_OUTPUT;

  res = TEEC_RegisterSharedMemory(&ctx, &g_outm);
  CHECK(res, "TEEC_RegisterSharedMemory: g_outm (out buf) failed");

  commit_buffer_tee_aes_ctr128_decrypt( length,
      iv, CTR_AES_IV_SIZE,  key, CTR_AES_KEY_SIZE, 0);

  TEEC_ReleaseSharedMemory(&g_shm);
  TEEC_ReleaseSharedMemory(&g_outm);

  return 0;
}

int TEE_crypto_init()
{
  TEEC_Result res;
  TEEC_UUID uuid = TA_AES_DECRYPTOR_UUID;
  uint32_t err_origin;

  if(g_iv.buffer)
    return TEEC_SUCCESS;

  res = TEEC_InitializeContext(NULL, &ctx);

  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

  res = TEEC_OpenSession(&ctx, &sess, &uuid,
             TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
      res, err_origin);

  if (!g_shm.buffer || !g_outm.buffer)
    allocate_mem();

 return res;
}

int
TEE_crypto_close() {

  if(!g_iv.buffer)
    return TEEC_SUCCESS;

  free_mem();

  TEEC_CloseSession(&sess);
  TEEC_FinalizeContext(&ctx);
  return TEEC_SUCCESS;
}
