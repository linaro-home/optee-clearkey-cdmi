/*
 * Copyright (c) 2018, Linaro Limited
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
 * liABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include "clearkey_platform.h"
#include "include/uapi/linux/ion.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "logging.h"
#include "ion/ion.h"
/*
 * Secure memory implementation is platform specified. For example,
 * a library called 'secure sedget library' is applied on platform
 * Juno + LT for secure memory related usage, such as fd retrieving.
 * Uses preprocessor to decide which implementation is applied.
 */
#ifdef USE_SEDGET_VIDEO
#include "sedget_video.h"
#elif defined(SDP_USES_NATIVE_HANDLE)
#include <cutils/native_handle.h>
#endif

int clearkey_plat_get_mem_fd(void *mem_handle)
{
#ifdef USE_SEDGET_VIDEO
	return sedget_get_mem_fd((sedget_protected_buffer *)mem_handle);
#elif defined(SDP_USES_NATIVE_HANDLE)
	native_handle_t *handle = (native_handle_t *)mem_handle;
	return handle->data[0];
#else
	return -1;
#endif
}

#ifdef SDP_PROTOTYPE

/* SDP protoype test functions to help validate
 * decryption into a SDP buffer on platforms which
 * don't already have a secure codec and therefore
 * don't get passed a buffer to decrypt method */

int allocate_ion_buffer(size_t size, int heap_id)
{
	struct ion_allocation_data alloc_data;
	struct ion_handle_data hdl_data;
	struct ion_fd_data fd_data;
	int ion;
	int fd = -1;

	ion = open("/dev/ion", O_RDWR);
	if (ion < 0) {
		FP("Error; failed to open /dev/ion\n");
		return fd;
	}

	if (heap_id < 0)
	  heap_id = ION_HEAP_TYPE_UNMAPPED;

	FP("Allocate in ION heap '%s'\n",
		heap_id == ION_HEAP_TYPE_SYSTEM ? "system" :
		heap_id == ION_HEAP_TYPE_SYSTEM_CONTIG ? "system contig" :
		heap_id == ION_HEAP_TYPE_CARVEOUT ? "carveout" :
		heap_id == ION_HEAP_TYPE_CHUNK ? "chunk" :
		heap_id == ION_HEAP_TYPE_DMA ? "dma" :
		heap_id == ION_HEAP_TYPE_UNMAPPED ? "unmapped" :
		"custom");

	alloc_data.len = size;
	alloc_data.align = 0;
	alloc_data.flags = 0;
	alloc_data.heap_id_mask = 1 << heap_id;
	if (ioctl(ion, ION_IOC_ALLOC, &alloc_data) == -1)
		goto out;

	fd_data.handle = alloc_data.handle;
	if (ioctl(ion, ION_IOC_SHARE, &fd_data) != -1)
		fd = fd_data.fd;

	hdl_data.handle = alloc_data.handle;
	(void)ioctl(ion, ION_IOC_FREE, &hdl_data);
out:
	close(ion);
	return fd;
}

int ion_map_and_memcpy(unsigned char* out_data,
                uint32_t length,
                int secure_fd,
                uint32_t blockOffset)
{
  /* To allow prototyping SDP, map the secure buffer
     (it is not actually protected) and copy data into the destination
     buffer. */
  ion_user_handle_t ion_user_handle = -1;
  unsigned char *mapped_secure_buf = NULL;
  int map_fd = -1;
  int ion_fd;
  int ret = 0;

  ion_fd = open("/dev/ion", O_RDWR);
  if (ion_fd < 0) {
    FP("Error; failed to open /dev/ion\n");
    ret = ion_fd;
    goto error;
  }

  ret = ion_import(ion_fd, secure_fd, &ion_user_handle);
  if (ret < 0) {
    FP("Cannot import secure buffer\n");
    goto error1;
  }

  ret = ion_map(ion_fd, ion_user_handle, length, PROT_READ | PROT_WRITE,
		MAP_SHARED, 0, &mapped_secure_buf, &map_fd);
  if(ret < 0) {
    FP("Cannot map secure buffer\n");
    goto error2;
  }

  memcpy(out_data, mapped_secure_buf + blockOffset, length);
  munmap(mapped_secure_buf, length);
  close(map_fd);

error2:
  ion_free(ion_fd, ion_user_handle);
  ion_user_handle = -1;
error1:
  close(ion_fd);
error:
  return ret;
}
#endif
