/*
 * Copyright (c) 2010-2011 Broadcom Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>

#include "vchiq.h"
#include "vchiq_cfg.h"
#include "vchiq_ioctl.h"
#include "interface/vchi/vchi.h"
#include "interface/vchi/common/endian.h"
#include "interface/vcos/vcos.h"

#define VCHIQ_MAX_INSTANCE_SERVICES 32
#define MSGBUF_SIZE (VCHIQ_MAX_MSG_SIZE + sizeof(VCHIQ_HEADER_T))

#define RETRY(r,x) do { r = x; } while ((r == -1) && (errno == EINTR))

#define VCOS_LOG_CATEGORY (&vchiq_lib_log_category)

typedef struct vchiq_service_struct
{
   VCHIQ_SERVICE_BASE_T base;
   int handle;
   int fd;
   VCHI_CALLBACK_T vchi_callback;
   void *peek_buf;
   int peek_size;
   int client_id;
} VCHIQ_SERVICE_T;

typedef struct vchiq_service_struct VCHI_SERVICE_T;

struct vchiq_instance_struct
{
   int fd;
   int initialised;
   int connected;
   VCOS_THREAD_T completion_thread;
   VCOS_MUTEX_T mutex;
   int used_services;
   VCHIQ_SERVICE_T services[VCHIQ_MAX_INSTANCE_SERVICES];
} vchiq_instance;

typedef struct vchiq_instance_struct VCHI_STATE_T;

/* Local data */
static VCOS_LOG_LEVEL_T vchiq_default_lib_log_level = VCOS_LOG_WARN;
static VCOS_LOG_CAT_T vchiq_lib_log_category;
static VCOS_MUTEX_T vchiq_lib_mutex;
static void *free_msgbufs;


/* Local utility functions */
static VCHIQ_INSTANCE_T
vchiq_lib_init(void);

static void *completion_thread(void *);

static VCHIQ_STATUS_T
create_service(VCHIQ_INSTANCE_T instance,
   const VCHIQ_SERVICE_PARAMS_T *params,
   VCHI_CALLBACK_T vchi_callback,
   int is_open,
   VCHIQ_SERVICE_HANDLE_T *pservice);

static int
fill_peek_buf(VCHI_SERVICE_T *service,
   VCHI_FLAGS_T flags);

static void *
alloc_msgbuf(void);

static void
free_msgbuf(void *buf);

static __inline int
is_valid_instance(VCHIQ_INSTANCE_T instance)
{
   return (instance == &vchiq_instance) && (instance->initialised > 0);
}

static __inline int
is_valid_service(VCHIQ_SERVICE_T *service)
{
   return ((service != NULL) && (service->fd != VCHIQ_INVALID_HANDLE));
}

/*
 * VCHIQ API
 */

VCHIQ_STATUS_T
vchiq_initialise(VCHIQ_INSTANCE_T *pinstance)
{
   VCHIQ_INSTANCE_T instance;

   instance = vchiq_lib_init();

   vcos_log_trace( "%s: returning instance handle %p", __func__, instance );

   *pinstance = instance;

   return (instance != NULL) ? VCHIQ_SUCCESS : VCHIQ_ERROR;
}

VCHIQ_STATUS_T
vchiq_shutdown(VCHIQ_INSTANCE_T instance)
{
   vcos_log_trace( "%s called", __func__ );

   if (!is_valid_instance(instance))
      return VCHIQ_ERROR;

   vcos_mutex_lock(&instance->mutex);

   if (instance->initialised == 1)
   {
      int i;

      instance->initialised = -1; /* Enter limbo */

      /* Remove all services */

      for (i = 0; i < instance->used_services; i++)
      {
         if (instance->services[i].handle != VCHIQ_INVALID_HANDLE)
         {
            vchiq_remove_service(&instance->services[i].base);
            instance->services[i].handle = VCHIQ_INVALID_HANDLE;
         }
      }

      if (instance->connected)
      {
         int ret;
         RETRY(ret, ioctl(instance->fd, VCHIQ_IOC_SHUTDOWN, 0));
         vcos_assert(ret == 0);
         vcos_thread_join(&instance->completion_thread, NULL);
         instance->connected = 0;
      }

      close(instance->fd);
      instance->fd = -1;
   }
   else if (instance->initialised > 1)
   {
      instance->initialised--;
   }

   vcos_mutex_unlock(&instance->mutex);

   vcos_global_lock();

   if (instance->initialised == -1)
   {
      vcos_mutex_delete(&instance->mutex);
      instance->initialised = 0;
   }

   vcos_global_unlock();

   vcos_log_trace( "%s returning", __func__ );

   return VCHIQ_SUCCESS;
}

VCHIQ_STATUS_T
vchiq_connect(VCHIQ_INSTANCE_T instance)
{
   VCHIQ_STATUS_T status = VCHIQ_SUCCESS;

   vcos_log_trace( "%s called", __func__ );

   if (!is_valid_instance(instance))
      return VCHIQ_ERROR;

   vcos_mutex_lock(&instance->mutex);

   if (!instance->connected)
   {
      int ret = ioctl(instance->fd, VCHIQ_IOC_CONNECT, 0);
      if (ret == 0)
      {
         VCOS_THREAD_ATTR_T attrs;
         instance->connected = 1;
         vcos_thread_attr_init(&attrs);
         vcos_thread_create(&instance->completion_thread, "VCHIQ completion",
                            &attrs, completion_thread, instance);
      }
      else
      {
         status = VCHIQ_ERROR;
      }
   }

   vcos_mutex_unlock(&instance->mutex);

   return status;
}

VCHIQ_STATUS_T
vchiq_add_service(VCHIQ_INSTANCE_T instance,
   int fourcc,
   VCHIQ_CALLBACK_T callback,
   void *userdata,
   VCHIQ_SERVICE_HANDLE_T *pservice)
{
   VCHIQ_SERVICE_PARAMS_T params;

   params.fourcc        = fourcc;
   params.callback      = callback;
   params.userdata      = userdata;
   params.version       = 0;
   params.version_min   = 0;

   return vchiq_add_service_params(instance, &params, pservice);
}

VCHIQ_STATUS_T
vchiq_open_service(VCHIQ_INSTANCE_T instance,
   int fourcc,
   VCHIQ_CALLBACK_T callback,
   void *userdata,
   VCHIQ_SERVICE_HANDLE_T *pservice)
{
   VCHIQ_SERVICE_PARAMS_T params;

   params.fourcc        = fourcc;
   params.callback      = callback;
   params.userdata      = userdata;
   params.version       = 0;
   params.version_min   = 0;

   return vchiq_open_service_params(instance, &params, pservice);
}

VCHIQ_STATUS_T
vchiq_add_service_params(VCHIQ_INSTANCE_T instance,
   const VCHIQ_SERVICE_PARAMS_T *params,
   VCHIQ_SERVICE_HANDLE_T *pservice)
{
   VCHIQ_STATUS_T status;

   vcos_log_trace( "%s called fourcc = 0x%08x (%c%c%c%c)",
                   __func__,
                   params->fourcc,
                   (params->fourcc >> 24) & 0xff,
                   (params->fourcc >> 16) & 0xff,
                   (params->fourcc >>  8) & 0xff,
                   (params->fourcc      ) & 0xff );

   if (!params->callback)
      return VCHIQ_ERROR;

   if (!is_valid_instance(instance))
      return VCHIQ_ERROR;

   status = create_service(instance,
      params,
      NULL/*vchi_callback*/,
      0/*!open*/,
      pservice);

   vcos_log_trace( "%s returning service handle = 0x%08x", __func__, (uint32_t)*pservice );

   return status;
}

VCHIQ_STATUS_T
vchiq_open_service_params(VCHIQ_INSTANCE_T instance,
   const VCHIQ_SERVICE_PARAMS_T *params,
   VCHIQ_SERVICE_HANDLE_T *pservice)
{
   VCHIQ_STATUS_T status;

   vcos_log_trace( "%s called fourcc = 0x%08x (%c%c%c%c)",
                   __func__,
                   params->fourcc,
                   (params->fourcc >> 24) & 0xff,
                   (params->fourcc >> 16) & 0xff,
                   (params->fourcc >>  8) & 0xff,
                   (params->fourcc      ) & 0xff );

   if (!params->callback)
      return VCHIQ_ERROR;

   if (!is_valid_instance(instance))
      return VCHIQ_ERROR;

   status = create_service(instance,
      params,
      NULL/*vchi_callback*/,
      1/*open*/,
      pservice);

   vcos_log_trace( "%s returning service handle = 0x%08x", __func__, (uint32_t)*pservice );

   return status;
}

VCHIQ_STATUS_T
vchiq_close_service(VCHIQ_SERVICE_HANDLE_T handle)
{
   VCHIQ_SERVICE_T *service = (VCHIQ_SERVICE_T *)handle;
   int ret;

   vcos_log_trace( "%s called service handle = 0x%08x", __func__, (uint32_t)handle );

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   RETRY(ret,ioctl(service->fd, VCHIQ_IOC_CLOSE_SERVICE, service->handle));

   if (ret != 0)
      return VCHIQ_ERROR;

   service->handle = VCHIQ_INVALID_HANDLE;
   return VCHIQ_SUCCESS;
}

VCHIQ_STATUS_T
vchiq_remove_service(VCHIQ_SERVICE_HANDLE_T handle)
{
   VCHIQ_SERVICE_T *service = (VCHIQ_SERVICE_T *)handle;
   int ret;

   vcos_log_trace( "%s called service handle = 0x%08x", __func__, (uint32_t)handle );

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   RETRY(ret,ioctl(service->fd, VCHIQ_IOC_REMOVE_SERVICE, service->handle));

   if (ret != 0)
      return VCHIQ_ERROR;

   service->handle = VCHIQ_INVALID_HANDLE;
   return VCHIQ_SUCCESS;
}

VCHIQ_STATUS_T
vchiq_queue_message(VCHIQ_SERVICE_HANDLE_T handle,
   const VCHIQ_ELEMENT_T *elements,
   int count)
{
   VCHIQ_SERVICE_T *service = (VCHIQ_SERVICE_T *)handle;
   VCHIQ_QUEUE_MESSAGE_T args;
   int ret;

   vcos_log_trace( "%s called service handle = 0x%08x", __func__, (uint32_t)handle );

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   args.handle = service->handle;
   args.elements = elements;
   args.count = count;
   RETRY(ret, ioctl(service->fd, VCHIQ_IOC_QUEUE_MESSAGE, &args));

   return (ret >= 0) ? VCHIQ_SUCCESS : VCHIQ_ERROR;
}

void
vchiq_release_message(VCHIQ_SERVICE_HANDLE_T handle,
   VCHIQ_HEADER_T *header)
{
   vcos_log_trace( "%s handle=%08x, header=%x", __func__, (uint32_t)handle, (uint32_t)header );

   free_msgbuf(header);
}

VCHIQ_STATUS_T
vchiq_queue_bulk_transmit(VCHIQ_SERVICE_HANDLE_T handle,
   const void *data,
   int size,
   void *userdata)
{
   VCHIQ_SERVICE_T *service = (VCHIQ_SERVICE_T *)handle;
   VCHIQ_QUEUE_BULK_TRANSFER_T args;
   int ret;

   vcos_log_trace( "%s called service handle = 0x%08x", __func__, (uint32_t)handle );

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   args.handle = service->handle;
   args.data = (void *)data;
   args.size = size;
   args.userdata = userdata;
   args.mode = VCHIQ_BULK_MODE_CALLBACK;
   RETRY(ret, ioctl(service->fd, VCHIQ_IOC_QUEUE_BULK_TRANSMIT, &args));

   return (ret >= 0) ? VCHIQ_SUCCESS : VCHIQ_ERROR;
}

VCHIQ_STATUS_T
vchiq_queue_bulk_receive(VCHIQ_SERVICE_HANDLE_T handle,
   void *data,
   int size,
   void *userdata)
{
   VCHIQ_SERVICE_T *service = (VCHIQ_SERVICE_T *)handle;
   VCHIQ_QUEUE_BULK_TRANSFER_T args;
   int ret;

   vcos_log_trace( "%s called service handle = 0x%08x", __func__, (uint32_t)handle );

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   args.handle = service->handle;
   args.data = data;
   args.size = size;
   args.userdata = userdata;
   args.mode = VCHIQ_BULK_MODE_CALLBACK;
   RETRY(ret, ioctl(service->fd, VCHIQ_IOC_QUEUE_BULK_RECEIVE, &args));

   return (ret >= 0) ? VCHIQ_SUCCESS : VCHIQ_ERROR;
}

VCHIQ_STATUS_T
vchiq_queue_bulk_transmit_handle(VCHIQ_SERVICE_HANDLE_T handle,
   VCHI_MEM_HANDLE_T memhandle,
   const void *offset,
   int size,
   void *userdata)
{
   vcos_assert(memhandle == VCHI_MEM_HANDLE_INVALID);

   vcos_log_trace( "%s called service handle = 0x%08x", __func__, (uint32_t)handle );

   return vchiq_queue_bulk_transmit(handle, offset, size, userdata);
}

VCHIQ_STATUS_T
vchiq_queue_bulk_receive_handle(VCHIQ_SERVICE_HANDLE_T handle,
   VCHI_MEM_HANDLE_T memhandle,
   void *offset,
   int size,
   void *userdata)
{
   vcos_assert(memhandle == VCHI_MEM_HANDLE_INVALID);

   vcos_log_trace( "%s called service handle = 0x%08x", __func__, (uint32_t)handle );

   return vchiq_queue_bulk_receive(handle, offset, size, userdata);
}

VCHIQ_STATUS_T
vchiq_bulk_transmit(VCHIQ_SERVICE_HANDLE_T handle,
   const void *data,
   int size,
   void *userdata,
   VCHIQ_BULK_MODE_T mode)
{
   VCHIQ_SERVICE_T *service = (VCHIQ_SERVICE_T *)handle;
   VCHIQ_QUEUE_BULK_TRANSFER_T args;
   int ret;

   vcos_log_trace( "%s called service handle = 0x%08x", __func__, (uint32_t)handle );

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   args.handle = service->handle;
   args.data = (void *)data;
   args.size = size;
   args.userdata = userdata;
   args.mode = mode;
   RETRY(ret, ioctl(service->fd, VCHIQ_IOC_QUEUE_BULK_TRANSMIT, &args));

   return (ret >= 0) ? VCHIQ_SUCCESS : VCHIQ_ERROR;
}

VCHIQ_STATUS_T
vchiq_bulk_receive(VCHIQ_SERVICE_HANDLE_T handle,
   void *data,
   int size,
   void *userdata,
   VCHIQ_BULK_MODE_T mode)
{
   VCHIQ_SERVICE_T *service = (VCHIQ_SERVICE_T *)handle;
   VCHIQ_QUEUE_BULK_TRANSFER_T args;
   int ret;

   vcos_log_trace( "%s called service handle = 0x%08x", __func__, (uint32_t)handle );

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   args.handle = service->handle;
   args.data = data;
   args.size = size;
   args.userdata = userdata;
   args.mode = mode;
   RETRY(ret, ioctl(service->fd, VCHIQ_IOC_QUEUE_BULK_RECEIVE, &args));

   return (ret >= 0) ? VCHIQ_SUCCESS : VCHIQ_ERROR;
}

VCHIQ_STATUS_T
vchiq_bulk_transmit_handle(VCHIQ_SERVICE_HANDLE_T handle,
   VCHI_MEM_HANDLE_T memhandle,
   const void *offset,
   int size,
   void *userdata,
   VCHIQ_BULK_MODE_T mode)
{
   vcos_assert(memhandle == VCHI_MEM_HANDLE_INVALID);

   return vchiq_bulk_transmit(handle, offset, size, userdata, mode);
}

VCHIQ_STATUS_T
vchiq_bulk_receive_handle(VCHIQ_SERVICE_HANDLE_T handle,
   VCHI_MEM_HANDLE_T memhandle,
   void *offset,
   int size,
   void *userdata,
   VCHIQ_BULK_MODE_T mode)
{
   vcos_assert(memhandle == VCHI_MEM_HANDLE_INVALID);

   return vchiq_bulk_receive(handle, offset, size, userdata, mode);
}

int
vchiq_get_client_id(VCHIQ_SERVICE_HANDLE_T handle)
{
   VCHIQ_SERVICE_T *service = (VCHIQ_SERVICE_T *)handle;

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   return ioctl(service->fd, VCHIQ_IOC_GET_CLIENT_ID, service->handle);
}

VCHIQ_STATUS_T
vchiq_get_config(VCHIQ_INSTANCE_T instance,
   int config_size,
   VCHIQ_CONFIG_T *pconfig)
{
   VCHIQ_GET_CONFIG_T args;
   int ret;

   if (!is_valid_instance(instance))
      return VCHIQ_ERROR;

   args.config_size = config_size;
   args.pconfig = pconfig;

   RETRY(ret, ioctl(instance->fd, VCHIQ_IOC_GET_CONFIG, &args));

   return (ret >= 0) ? VCHIQ_SUCCESS : VCHIQ_ERROR;
}

int32_t
vchiq_use_service( const VCHIQ_SERVICE_HANDLE_T handle )
{
   VCHIQ_SERVICE_T *service = (VCHIQ_SERVICE_T *)handle;
   int ret;

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   RETRY(ret,ioctl(service->fd, VCHIQ_IOC_USE_SERVICE, service->handle));
   return ret;
}

int32_t
vchiq_release_service( const VCHIQ_SERVICE_HANDLE_T handle )
{
    VCHIQ_SERVICE_T *service = (VCHIQ_SERVICE_T *)handle;
    int ret;
    RETRY(ret,ioctl(service->fd, VCHIQ_IOC_RELEASE_SERVICE, service->handle));
    return ret;
}

VCHIQ_STATUS_T
vchiq_set_service_option(VCHIQ_SERVICE_HANDLE_T handle,
   VCHIQ_SERVICE_OPTION_T option, int value)
{
   VCHIQ_SET_SERVICE_OPTION_T args;
   VCHIQ_SERVICE_T *service = (VCHIQ_SERVICE_T *)handle;
   int ret;

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   args.handle = service->handle;
   args.option = option;
   args.value  = value;

   RETRY(ret, ioctl(service->fd, VCHIQ_IOC_SET_SERVICE_OPTION, &args));

   return (ret >= 0) ? VCHIQ_SUCCESS : VCHIQ_ERROR;
}

/*
 * VCHI API
 */

/* ----------------------------------------------------------------------
 * return pointer to the mphi message driver function table
 * -------------------------------------------------------------------- */
const VCHI_MESSAGE_DRIVER_T *
vchi_mphi_message_driver_func_table( void )
{
   return NULL;
}

/* ----------------------------------------------------------------------
 * return a pointer to the 'single' connection driver fops
 * -------------------------------------------------------------------- */
const VCHI_CONNECTION_API_T *
single_get_func_table( void )
{
   return NULL;
}

VCHI_CONNECTION_T *
vchi_create_connection( const VCHI_CONNECTION_API_T * function_table,
   const VCHI_MESSAGE_DRIVER_T * low_level )
{
   vcos_unused(function_table);
   vcos_unused(low_level);

   return NULL;
}

/***********************************************************
 * Name: vchi_msg_peek
 *
 * Arguments:  const VCHI_SERVICE_HANDLE_T handle,
 *             void **data,
 *             uint32_t *msg_size,
 *             VCHI_FLAGS_T flags
 *
 * Description: Routine to return a pointer to the current message (to allow in place processing)
 *              The message can be removed using vchi_msg_remove when you're finished
 *
 * Returns: int32_t - success == 0
 *
 ***********************************************************/
int32_t
vchi_msg_peek( VCHI_SERVICE_HANDLE_T handle,
   void **data,
   uint32_t *msg_size,
   VCHI_FLAGS_T flags )
{
   VCHI_SERVICE_T *service = (VCHI_SERVICE_T *)handle;
   int ret;

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   ret = fill_peek_buf(service, flags);

   if (ret == 0)
   {
      *data = service->peek_buf;
      *msg_size = service->peek_size;
   }

   return ret;
}

/***********************************************************
 * Name: vchi_msg_remove
 *
 * Arguments:  const VCHI_SERVICE_HANDLE_T handle,
 *
 * Description: Routine to remove a message (after it has been read with vchi_msg_peek)
 *
 * Returns: int32_t - success == 0
 *
 ***********************************************************/
int32_t
vchi_msg_remove( VCHI_SERVICE_HANDLE_T handle )
{
   VCHI_SERVICE_T *service = (VCHI_SERVICE_T *)handle;

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   /* Why would you call vchi_msg_remove without calling vchi_msg_peek first? */
   vcos_assert(service->peek_size >= 0);

   /* Invalidate the content but reuse the buffer */
   service->peek_size = -1;

   return 0;
}

/***********************************************************
 * Name: vchi_msg_queue
 *
 * Arguments:  VCHI_SERVICE_HANDLE_T handle,
 *             const void *data,
 *             uint32_t data_size,
 *             VCHI_FLAGS_T flags,
 *             void *msg_handle,
 *
 * Description: Thin wrapper to queue a message onto a connection
 *
 * Returns: int32_t - success == 0
 *
 ***********************************************************/
int32_t
vchi_msg_queue( VCHI_SERVICE_HANDLE_T handle,
   const void * data,
   uint32_t data_size,
   VCHI_FLAGS_T flags,
   void * msg_handle )
{
   VCHI_SERVICE_T *service = (VCHI_SERVICE_T *)handle;
   VCHIQ_QUEUE_MESSAGE_T args;
   VCHIQ_ELEMENT_T element = {data, data_size};
   int ret;

   vcos_unused(msg_handle);
   vcos_assert(flags == VCHI_FLAGS_BLOCK_UNTIL_QUEUED);

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   args.handle = service->handle;
   args.elements = &element;
   args.count = 1;
   RETRY(ret, ioctl(service->fd, VCHIQ_IOC_QUEUE_MESSAGE, &args));

   return ret;
}

/***********************************************************
 * Name: vchi_bulk_queue_receive
 *
 * Arguments:  VCHI_BULK_HANDLE_T handle,
 *             void *data_dst,
 *             const uint32_t data_size,
 *             VCHI_FLAGS_T flags
 *             void *bulk_handle
 *
 * Description: Routine to setup a rcv buffer
 *
 * Returns: int32_t - success == 0
 *
 ***********************************************************/
int32_t
vchi_bulk_queue_receive( VCHI_SERVICE_HANDLE_T handle,
   void * data_dst,
   uint32_t data_size,
   VCHI_FLAGS_T flags,
   void * bulk_handle )
{
   VCHI_SERVICE_T *service = (VCHI_SERVICE_T *)handle;
   VCHIQ_QUEUE_BULK_TRANSFER_T args;
   int ret;

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   switch ((int)flags) {
   case VCHI_FLAGS_CALLBACK_WHEN_OP_COMPLETE | VCHI_FLAGS_BLOCK_UNTIL_QUEUED:
      args.mode = VCHIQ_BULK_MODE_CALLBACK;
      break;
   case VCHI_FLAGS_BLOCK_UNTIL_OP_COMPLETE:
      args.mode = VCHIQ_BULK_MODE_BLOCKING;
      break;
   case VCHI_FLAGS_BLOCK_UNTIL_QUEUED:
   case VCHI_FLAGS_NONE:
      args.mode = VCHIQ_BULK_MODE_NOCALLBACK;
      break;
   default:
      vcos_assert(0);
      break;
   }

   args.handle = service->handle;
   args.data = data_dst;
   args.size = data_size;
   args.userdata = bulk_handle;
   RETRY(ret, ioctl(service->fd, VCHIQ_IOC_QUEUE_BULK_RECEIVE, &args));

   return ret;
}

/***********************************************************
 * Name: vchi_bulk_queue_transmit
 *
 * Arguments:  VCHI_BULK_HANDLE_T handle,
 *             const void *data_src,
 *             uint32_t data_size,
 *             VCHI_FLAGS_T flags,
 *             void *bulk_handle
 *
 * Description: Routine to transmit some data
 *
 * Returns: int32_t - success == 0
 *
 ***********************************************************/
int32_t
vchi_bulk_queue_transmit( VCHI_SERVICE_HANDLE_T handle,
   const void * data_src,
   uint32_t data_size,
   VCHI_FLAGS_T flags,
   void * bulk_handle )
{
   VCHI_SERVICE_T *service = (VCHI_SERVICE_T *)handle;
   VCHIQ_QUEUE_BULK_TRANSFER_T args;
   int ret;

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   switch ((int)flags) {
   case VCHI_FLAGS_CALLBACK_WHEN_OP_COMPLETE | VCHI_FLAGS_BLOCK_UNTIL_QUEUED:
      args.mode = VCHIQ_BULK_MODE_CALLBACK;
      break;
   case VCHI_FLAGS_BLOCK_UNTIL_DATA_READ:
   case VCHI_FLAGS_BLOCK_UNTIL_OP_COMPLETE:
      args.mode = VCHIQ_BULK_MODE_BLOCKING;
      break;
   case VCHI_FLAGS_BLOCK_UNTIL_QUEUED:
   case VCHI_FLAGS_NONE:
      args.mode = VCHIQ_BULK_MODE_NOCALLBACK;
      break;
   default:
      vcos_assert(0);
      break;
   }

   args.handle = service->handle;
   args.data = (void *)data_src;
   args.size = data_size;
   args.userdata = bulk_handle;
   RETRY(ret, ioctl(service->fd, VCHIQ_IOC_QUEUE_BULK_TRANSMIT, &args));

   return ret;
}

/***********************************************************
 * Name: vchi_msg_dequeue
 *
 * Arguments:  VCHI_SERVICE_HANDLE_T handle,
 *             void *data,
 *             uint32_t max_data_size_to_read,
 *             uint32_t *actual_msg_size
 *             VCHI_FLAGS_T flags
 *
 * Description: Routine to dequeue a message into the supplied buffer
 *
 * Returns: int32_t - success == 0
 *
 ***********************************************************/
int32_t
vchi_msg_dequeue( VCHI_SERVICE_HANDLE_T handle,
   void *data,
   uint32_t max_data_size_to_read,
   uint32_t *actual_msg_size,
   VCHI_FLAGS_T flags )
{
   VCHI_SERVICE_T *service = (VCHI_SERVICE_T *)handle;
   VCHIQ_DEQUEUE_MESSAGE_T args;
   int ret;

   vcos_assert(flags == VCHI_FLAGS_NONE || flags == VCHI_FLAGS_BLOCK_UNTIL_OP_COMPLETE);

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   if (service->peek_size >= 0)
   {
      fprintf(stderr, "vchi_msg_dequeue -> using peek buffer\n");
      if ((uint32_t)service->peek_size <= max_data_size_to_read)
      {
         memcpy(data, service->peek_buf, service->peek_size);
         *actual_msg_size = service->peek_size;
         /* Invalidate the peek data, but retain the buffer */
         service->peek_size = -1;
         ret = 0;
      }
      else
      {
         ret = -1;
      }
   }
   else
   {
      args.handle = service->handle;
      args.blocking = (flags == VCHI_FLAGS_BLOCK_UNTIL_OP_COMPLETE);
      args.bufsize = max_data_size_to_read;
      args.buf = data;
      RETRY(ret, ioctl(service->fd, VCHIQ_IOC_DEQUEUE_MESSAGE, &args));
      if (ret >= 0)
      {
         *actual_msg_size = ret;
         ret = 0;
      }
   }

   if ((ret < 0) && (errno != EWOULDBLOCK))
      fprintf(stderr, "vchi_msg_dequeue -> %d(%d)\n", ret, errno);

   return ret;
}

/***********************************************************
 * Name: vchi_msg_queuev
 *
 * Arguments:  VCHI_SERVICE_HANDLE_T handle,
 *             const void *data,
 *             uint32_t data_size,
 *             VCHI_FLAGS_T flags,
 *             void *msg_handle
 *
 * Description: Thin wrapper to queue a message onto a connection
 *
 * Returns: int32_t - success == 0
 *
 ***********************************************************/

vcos_static_assert(sizeof(VCHI_MSG_VECTOR_T) == sizeof(VCHIQ_ELEMENT_T));
vcos_static_assert(offsetof(VCHI_MSG_VECTOR_T, vec_base) == offsetof(VCHIQ_ELEMENT_T, data));
vcos_static_assert(offsetof(VCHI_MSG_VECTOR_T, vec_len) == offsetof(VCHIQ_ELEMENT_T, size));

int32_t
vchi_msg_queuev( VCHI_SERVICE_HANDLE_T handle,
   VCHI_MSG_VECTOR_T * vector,
   uint32_t count,
   VCHI_FLAGS_T flags,
   void *msg_handle )
{
   VCHI_SERVICE_T *service = (VCHI_SERVICE_T *)handle;
   VCHIQ_QUEUE_MESSAGE_T args;
   int ret;

   vcos_unused(msg_handle);

   vcos_assert(flags == VCHI_FLAGS_BLOCK_UNTIL_QUEUED);

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   args.handle = service->handle;
   args.elements = (const VCHIQ_ELEMENT_T *)vector;
   args.count = count;
   RETRY(ret, ioctl(service->fd, VCHIQ_IOC_QUEUE_MESSAGE, &args));

   return ret;
}

/***********************************************************
 * Name: vchi_held_msg_release
 *
 * Arguments:  VCHI_HELD_MSG_T *message
 *
 * Description: Routine to release a held message (after it has been read with vchi_msg_hold)
 *
 * Returns: int32_t - success == 0
 *
 ***********************************************************/
int32_t
vchi_held_msg_release( VCHI_HELD_MSG_T *message )
{
   int ret = -1;

   if (message && message->message && !message->service)
   {
      free_msgbuf(message->message);
      ret = 0;
   }

   return ret;
}

/***********************************************************
 * Name: vchi_msg_hold
 *
 * Arguments:  VCHI_SERVICE_HANDLE_T handle,
 *             void **data,
 *             uint32_t *msg_size,
 *             VCHI_FLAGS_T flags,
 *             VCHI_HELD_MSG_T *message_handle
 *
 * Description: Routine to return a pointer to the current message (to allow in place processing)
 *              The message is dequeued - don't forget to release the message using
 *              vchi_held_msg_release when you're finished
 *
 * Returns: int32_t - success == 0
 *
 ***********************************************************/
int32_t
vchi_msg_hold( VCHI_SERVICE_HANDLE_T handle,
   void **data,
   uint32_t *msg_size,
   VCHI_FLAGS_T flags,
   VCHI_HELD_MSG_T *message_handle )
{
   VCHI_SERVICE_T *service = (VCHI_SERVICE_T *)handle;
   int ret;

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   ret = fill_peek_buf(service, flags);

   if (ret == 0)
   {
      *data = service->peek_buf;
      *msg_size = service->peek_size;

      message_handle->message = service->peek_buf;
      message_handle->service = NULL;

      service->peek_size = -1;
      service->peek_buf = NULL;
   }

   return 0;
}

/***********************************************************
 * Name: vchi_initialise
 *
 * Arguments: VCHI_INSTANCE_T *instance_handle
 *            VCHI_CONNECTION_T **connections
 *            const uint32_t num_connections
 *
 * Description: Initialises the hardware but does not transmit anything
 *              When run as a Host App this will be called twice hence the need
 *              to malloc the state information
 *
 * Returns: 0 if successful, failure otherwise
 *
 ***********************************************************/
int32_t
vchi_initialise( VCHI_INSTANCE_T *instance_handle )
{
   VCHIQ_INSTANCE_T instance;

   instance = vchiq_lib_init();

   vcos_log_trace( "%s: returning instance handle %p", __func__, instance );

   *instance_handle = (VCHI_INSTANCE_T)instance;

   return (instance != NULL) ? 0 : -1;
}

/***********************************************************
 * Name: vchi_connect
 *
 * Arguments: VCHI_CONNECTION_T **connections
 *            const uint32_t num_connections
 *            VCHI_INSTANCE_T instance_handle )
 *
 * Description: Starts the command service on each connection,
 *              causing INIT messages to be pinged back and forth
 *
 * Returns: 0 if successful, failure otherwise
 *
 ***********************************************************/
int32_t
vchi_connect( VCHI_CONNECTION_T **connections,
   const uint32_t num_connections,
   VCHI_INSTANCE_T instance_handle )
{
   VCHIQ_STATUS_T status;

   vcos_unused(connections);
   vcos_unused(num_connections);

   status = vchiq_connect((VCHIQ_INSTANCE_T)instance_handle);

   return (status == VCHIQ_SUCCESS) ? 0 : -1;
}


/***********************************************************
 * Name: vchi_disconnect
 *
 * Arguments: VCHI_INSTANCE_T instance_handle
 *
 * Description: Stops the command service on each connection,
 *              causing DE-INIT messages to be pinged back and forth
 *
 * Returns: 0 if successful, failure otherwise
 *
 ***********************************************************/
int32_t
vchi_disconnect( VCHI_INSTANCE_T instance_handle )
{
   VCHIQ_STATUS_T status;
   
   status = vchiq_shutdown((VCHIQ_INSTANCE_T)instance_handle);

   return (status == VCHIQ_SUCCESS) ? 0 : -1;
}


/***********************************************************
 * Name: vchi_service_open
 * Name: vchi_service_create
 *
 * Arguments: VCHI_INSTANCE_T *instance_handle
 *            SERVICE_CREATION_T *setup,
 *            VCHI_SERVICE_HANDLE_T *handle
 *
 * Description: Routine to open a service
 *
 * Returns: int32_t - success == 0
 *
 ***********************************************************/
int32_t
vchi_service_open( VCHI_INSTANCE_T instance_handle,
   SERVICE_CREATION_T *setup,
   VCHI_SERVICE_HANDLE_T *handle )
{
   VCHIQ_SERVICE_PARAMS_T params;
   VCHIQ_STATUS_T status;

   memset(&params, 0, sizeof(params));
   params.fourcc = setup->service_id;
   params.userdata = setup->callback_param;

   status = create_service((VCHIQ_INSTANCE_T)instance_handle,
      &params,
      setup->callback,
      1/*open*/,
      (VCHIQ_SERVICE_HANDLE_T *)handle);

   return (status == VCHIQ_SUCCESS) ? 0 : -1;
}

int32_t
vchi_service_create( VCHI_INSTANCE_T instance_handle,
   SERVICE_CREATION_T *setup, VCHI_SERVICE_HANDLE_T *handle )
{
   VCHIQ_SERVICE_PARAMS_T params;
   VCHIQ_STATUS_T status;

   memset(&params, 0, sizeof(params));
   params.fourcc = setup->service_id;
   params.userdata = setup->callback_param;

   status = create_service((VCHIQ_INSTANCE_T)instance_handle,
      &params,
      setup->callback,
      0/*!open*/,
      (VCHIQ_SERVICE_HANDLE_T *)handle);

   return (status == VCHIQ_SUCCESS) ? 0 : -1;
}

int32_t
vchi_service_close( const VCHI_SERVICE_HANDLE_T handle )
{
   VCHI_SERVICE_T *service = (VCHI_SERVICE_T *)handle;
   int ret;

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   RETRY(ret,ioctl(service->fd, VCHIQ_IOC_REMOVE_SERVICE, service->handle));

   if (ret == 0)
      service->handle = VCHIQ_INVALID_HANDLE;

   return ret;
}

int32_t
vchi_service_destroy( const VCHI_SERVICE_HANDLE_T handle )
{
   VCHI_SERVICE_T *service = (VCHI_SERVICE_T *)handle;
   int ret;

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   RETRY(ret,ioctl(service->fd, VCHIQ_IOC_REMOVE_SERVICE, service->handle));

   if (ret == 0)
      service->handle = VCHIQ_INVALID_HANDLE;

   return ret;
}

/* ----------------------------------------------------------------------
 * read a uint32_t from buffer.
 * network format is defined to be little endian
 * -------------------------------------------------------------------- */
uint32_t
vchi_readbuf_uint32( const void *_ptr )
{
   const unsigned char *ptr = _ptr;
   return ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24);
}

/* ----------------------------------------------------------------------
 * write a uint32_t to buffer.
 * network format is defined to be little endian
 * -------------------------------------------------------------------- */
void
vchi_writebuf_uint32( void *_ptr, uint32_t value )
{
   unsigned char *ptr = _ptr;
   ptr[0] = (unsigned char)((value >> 0)  & 0xFF);
   ptr[1] = (unsigned char)((value >> 8)  & 0xFF);
   ptr[2] = (unsigned char)((value >> 16) & 0xFF);
   ptr[3] = (unsigned char)((value >> 24) & 0xFF);
}

/* ----------------------------------------------------------------------
 * read a uint16_t from buffer.
 * network format is defined to be little endian
 * -------------------------------------------------------------------- */
uint16_t
vchi_readbuf_uint16( const void *_ptr )
{
   const unsigned char *ptr = _ptr;
   return ptr[0] | (ptr[1] << 8);
}

/* ----------------------------------------------------------------------
 * write a uint16_t into the buffer.
 * network format is defined to be little endian
 * -------------------------------------------------------------------- */
void
vchi_writebuf_uint16( void *_ptr, uint16_t value )
{
   unsigned char *ptr = _ptr;
   ptr[0] = (value >> 0)  & 0xFF;
   ptr[1] = (value >> 8)  & 0xFF;
}

/***********************************************************
 * Name: vchi_service_use
 *
 * Arguments: const VCHI_SERVICE_HANDLE_T handle
 *
 * Description: Routine to increment refcount on a service
 *
 * Returns: void
 *
 ***********************************************************/
int32_t
vchi_service_use( const VCHI_SERVICE_HANDLE_T handle )
{
   VCHI_SERVICE_T *service = (VCHI_SERVICE_T *)handle;
   int ret;

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   RETRY(ret,ioctl(service->fd, VCHIQ_IOC_USE_SERVICE, service->handle));
   return ret;
}

/***********************************************************
 * Name: vchi_service_release
 *
 * Arguments: const VCHI_SERVICE_HANDLE_T handle
 *
 * Description: Routine to decrement refcount on a service
 *
 * Returns: void
 *
 ***********************************************************/
int32_t vchi_service_release( const VCHI_SERVICE_HANDLE_T handle )
{
   VCHI_SERVICE_T *service = (VCHI_SERVICE_T *)handle;
   int ret;

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   RETRY(ret,ioctl(service->fd, VCHIQ_IOC_RELEASE_SERVICE, service->handle));
   return ret;
}

/***********************************************************
 * Name: vchiq_dump_phys_mem
 *
 * Arguments: const VCHI_SERVICE_HANDLE_T handle
 *            void *buffer
 *            size_t num_bytes
 *
 * Description: Dumps the physical memory associated with
 *              a buffer.
 *
 * Returns: void
 *
 ***********************************************************/
VCHIQ_STATUS_T vchiq_dump_phys_mem( VCHIQ_SERVICE_HANDLE_T handle,
                             void *ptr,
                             size_t num_bytes )
{
   VCHIQ_SERVICE_T *service = (VCHIQ_SERVICE_T *)handle;
   VCHIQ_DUMP_MEM_T  dump_mem;
   int ret;

   if (!is_valid_service(service))
      return VCHIQ_ERROR;

   dump_mem.virt_addr = ptr;
   dump_mem.num_bytes = num_bytes;

   RETRY(ret,ioctl(service->fd, VCHIQ_IOC_DUMP_PHYS_MEM, &dump_mem));
   return (ret >= 0) ? VCHIQ_SUCCESS : VCHIQ_ERROR;
}



/*
 * Support functions
 */

static VCHIQ_INSTANCE_T
vchiq_lib_init(void)
{
   static int mutex_initialised = 0;
   static VCOS_MUTEX_T vchiq_lib_mutex;
   VCHIQ_INSTANCE_T instance = &vchiq_instance;

   vcos_global_lock();
   if (!mutex_initialised)
   {
      vcos_mutex_create(&vchiq_lib_mutex, "vchiq-init");

      vcos_log_set_level( &vchiq_lib_log_category, vchiq_default_lib_log_level );
      vcos_log_register( "vchiq_lib", &vchiq_lib_log_category );

      mutex_initialised = 1;
   }
   vcos_global_unlock();

   vcos_mutex_lock(&vchiq_lib_mutex);

   if (instance->initialised == 0)
   {
      instance->fd = open("/dev/vchiq", O_RDWR);
      if (instance->fd >= 0)
      {
         VCHIQ_GET_CONFIG_T args;
         VCHIQ_CONFIG_T config;
         int ret;
         args.config_size = sizeof(config);
         args.pconfig = &config;
         RETRY(ret, ioctl(instance->fd, VCHIQ_IOC_GET_CONFIG, &args));
         if ((ret == 0) && (config.version >= VCHIQ_VERSION_MIN) && (config.version_min <= VCHIQ_VERSION))
         {
            instance->used_services = 0;
            vcos_mutex_create(&instance->mutex, "VCHIQ instance");
            instance->initialised = 1;
         }
         else
         {
            if (ret == 0)
            {
               vcos_log_error("Incompatible VCHIQ library - driver version %d (min %d), library version %d (min %d)",
                  config.version, config.version_min, VCHIQ_VERSION, VCHIQ_VERSION_MIN);
            }
            else
            {
               vcos_log_error("Very incompatible VCHIQ library - cannot retrieve driver version");
            }
            close(instance->fd);
            instance = NULL;
         }
      }
      else
      {
         instance = NULL;
      }
   }
   else if (instance->initialised > 0)
   {
      instance->initialised++;
   }

   vcos_mutex_unlock(&vchiq_lib_mutex);

   return instance;
}

static void *
completion_thread(void *arg)
{
   VCHIQ_INSTANCE_T instance = (VCHIQ_INSTANCE_T)arg;
   VCHIQ_AWAIT_COMPLETION_T args;
   VCHIQ_COMPLETION_DATA_T completions[8];
   void *msgbufs[8];

   static const VCHI_CALLBACK_REASON_T vchiq_reason_to_vchi[] =
   {
      VCHI_CALLBACK_SERVICE_OPENED,        // VCHIQ_SERVICE_OPENED
      VCHI_CALLBACK_SERVICE_CLOSED,        // VCHIQ_SERVICE_CLOSED
      VCHI_CALLBACK_MSG_AVAILABLE,         // VCHIQ_MESSAGE_AVAILABLE
      VCHI_CALLBACK_BULK_SENT,             // VCHIQ_BULK_TRANSMIT_DONE
      VCHI_CALLBACK_BULK_RECEIVED,         // VCHIQ_BULK_RECEIVE_DONE
      VCHI_CALLBACK_BULK_TRANSMIT_ABORTED, // VCHIQ_BULK_TRANSMIT_ABORTED
      VCHI_CALLBACK_BULK_RECEIVE_ABORTED,  // VCHIQ_BULK_RECEIVE_ABORTED
   };

   args.count = vcos_countof(completions);
   args.buf = completions;
   args.msgbufsize = MSGBUF_SIZE;
   args.msgbufcount = 0;
   args.msgbufs = msgbufs;

   while (1)
   {
      int ret, i;

      while ((unsigned int)args.msgbufcount < vcos_countof(msgbufs))
      {
         void *msgbuf = alloc_msgbuf();
         if (msgbuf)
         {
            msgbufs[args.msgbufcount++] = msgbuf;
         }
         else
         {
            fprintf(stderr, "vchiq_lib: failed to allocate a message buffer\n");
            vcos_demand(args.msgbufcount != 0);
         }
      }

      RETRY(ret, ioctl(instance->fd, VCHIQ_IOC_AWAIT_COMPLETION, &args));

      if (ret <= 0)
         break;

      for (i = 0; i < ret; i++)
      {
         VCHIQ_COMPLETION_DATA_T *completion = &completions[i];
         VCHIQ_SERVICE_T *service = (VCHIQ_SERVICE_T *)completion->service_userdata;
         if (service->base.callback)
         {
            vcos_log_trace( "callback(%x, %x, %x, %x)",
               completion->reason, (uint32_t)completion->header,
               (uint32_t)&service->base, (uint32_t)completion->bulk_userdata );
            service->base.callback(completion->reason, completion->header,
               &service->base, completion->bulk_userdata);
         }
         else if (service->vchi_callback)
         {
            VCHI_CALLBACK_REASON_T vchi_reason =
               vchiq_reason_to_vchi[completion->reason];
            service->vchi_callback(service->base.userdata, vchi_reason, completion->bulk_userdata);
         }
      }
   }
   return NULL;
}

static VCHIQ_STATUS_T
create_service(VCHIQ_INSTANCE_T instance,
   const VCHIQ_SERVICE_PARAMS_T *params,
   VCHI_CALLBACK_T vchi_callback,
   int is_open,
   VCHIQ_SERVICE_HANDLE_T *pservice)
{
   VCHIQ_SERVICE_T *service = NULL;
   VCHIQ_STATUS_T status = VCHIQ_SUCCESS;
   int i;

   if (!is_valid_instance(instance))
      return VCHIQ_ERROR;

   vcos_mutex_lock(&instance->mutex);

   /* Find a free service */
   if (is_open)
   {
      /* Find a free service */
      for (i = 0; i < instance->used_services; i++)
      {
         if (instance->services[i].handle == VCHIQ_INVALID_HANDLE)
         {
            service = &instance->services[i];
            break;
         }
      }
   }
   else
   {
      for (i = (instance->used_services - 1); i >= 0; i--)
      {
         VCHIQ_SERVICE_T *srv = &instance->services[i];
         if (srv->handle == VCHIQ_INVALID_HANDLE)
         {
            service = srv;
         }
         else if (
            (srv->base.fourcc == params->fourcc) &&
            ((srv->base.callback != params->callback) ||
            (srv->vchi_callback != vchi_callback)))
         {
            /* There is another server using this fourcc which doesn't match */
            service = NULL;
            status = VCHIQ_ERROR;
            break;
         }
      }
   }

   if (!service && (status == VCHIQ_SUCCESS) &&
      (instance->used_services < VCHIQ_MAX_INSTANCE_SERVICES))
      service = &instance->services[instance->used_services++];

   if (service)
   {
      VCHIQ_CREATE_SERVICE_T args;
      int ret;
      service->base.fourcc = params->fourcc;
      service->base.callback = params->callback;
      service->vchi_callback = vchi_callback;
      service->base.userdata = params->userdata;
      service->fd = instance->fd;
      service->peek_size = -1;
      service->peek_buf = NULL;

      args.params = *params;
      args.params.userdata = service;
      args.is_open = is_open;
      args.is_vchi = (params->callback == NULL);
      args.handle = -1; /* OUT parameter */
      RETRY(ret, ioctl(instance->fd, VCHIQ_IOC_CREATE_SERVICE, &args));
      if (ret == 0)
         service->handle = args.handle;
      else
         status = VCHIQ_ERROR;
   }

   *pservice = (status == VCHIQ_SUCCESS) ? &service->base : NULL;

   vcos_mutex_unlock(&instance->mutex);

   return status;
}

static int
fill_peek_buf(VCHI_SERVICE_T *service,
   VCHI_FLAGS_T flags)
{
   VCHIQ_DEQUEUE_MESSAGE_T args;
   int ret = 0;

   vcos_assert(flags == VCHI_FLAGS_NONE || flags == VCHI_FLAGS_BLOCK_UNTIL_OP_COMPLETE);

   if (service->peek_size < 0)
   {
      if (!service->peek_buf)
         service->peek_buf = alloc_msgbuf();

      if (service->peek_buf)
      {
         args.handle = service->handle;
         args.blocking = (flags == VCHI_FLAGS_BLOCK_UNTIL_OP_COMPLETE);
         args.bufsize = MSGBUF_SIZE;
         args.buf = service->peek_buf;

         RETRY(ret, ioctl(service->fd, VCHIQ_IOC_DEQUEUE_MESSAGE, &args));

         if (ret >= 0)
         {
            service->peek_size = ret;
            ret = 0;
         }
         else
         {
            ret = -1;
         }
      }
      else
      {
         ret = -1;
      }
   }

   return ret;
}


static void *
alloc_msgbuf(void)
{
   void *msgbuf;
   vcos_mutex_lock(&vchiq_lib_mutex);
   msgbuf = free_msgbufs;
   if (msgbuf)
      free_msgbufs = *(void **)msgbuf;
   vcos_mutex_unlock(&vchiq_lib_mutex);
   if (!msgbuf)
      msgbuf = malloc(MSGBUF_SIZE);
   return msgbuf;
}

static void
free_msgbuf(void *buf)
{
   vcos_mutex_lock(&vchiq_lib_mutex);
   *(void **)buf = free_msgbufs;
   free_msgbufs = buf;
   vcos_mutex_unlock(&vchiq_lib_mutex);
}
