/*
 * Copyright (c) 2018-2020, Linaro Limited
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

#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <fstream>
#include <iostream>
//#include <cdm_logging.h>

#define CDM_DLOG() std::cout

#include "socket_client_helper.h"

namespace WPEFramework {

int SocketClient::Connect(int f_SocketChannelId)
{
  int status = 0;
  struct sockaddr_un socketAddress;
  struct timeval timeout_tv;
	
  if(m_SocketFd >= 0) {
    CDM_DLOG() << "Socket connection already established, reuse connection";
    //Disconnect();
    return status;
  }

  if(f_SocketChannelId < 0) {
    CDM_DLOG() << "Invalid socket channel ID";
    status = -1;
    goto handle_error;
  }

  m_SocketFd = socket(AF_UNIX, SOCK_STREAM, 0);
  if(m_SocketFd < 0) {
    CDM_DLOG() << "Failure to create socket";
    status = -1;
    goto handle_error;
  }

  /* Use abstract socket (First byte is \0). */
  memset(&socketAddress, 0, sizeof(socketAddress));
  socketAddress.sun_family = AF_UNIX;
  sprintf(&socketAddress.sun_path[1], "opencdm_fd_communication_channel_0x%08x", f_SocketChannelId);

  CDM_DLOG() << "Connecting to socket (" << &socketAddress.sun_path[1] << ")";

  if(connect(m_SocketFd, (struct sockaddr *)&socketAddress, sizeof(socketAddress)) < 0) {
    CDM_DLOG() << "Failure to connect socket";
    status = -1;
    goto handle_error;
  }

  /* Configure a timeout for sendmsg(). This is to avoid an infinite wait. */
  timeout_tv.tv_sec = SOCKET_SEND_TIMEOUT;
  timeout_tv.tv_usec = 0;
  status = setsockopt(m_SocketFd, SOL_SOCKET, SO_SNDTIMEO, (const void *)&timeout_tv, sizeof(timeout_tv));
  if(status < 0) {
    CDM_DLOG() << "Cannot configure sendmsg timeout";
    goto handle_error;
  }

handle_error:
  if(status < 0) {
    Disconnect();
  }
  return status;
}


int SocketClient::SendFileDescriptor(int f_FileDescriptor, uint32_t f_Size)
{
  int status = 0;

  struct msghdr msg;
  struct iovec iov;

  /* Control message buffer contains the control message structure plus
   one file descriptor. */
  #define CMSG_SIZE (sizeof(struct cmsghdr) + sizeof(int))
  uint8_t cmsg_buffer[CMSG_SIZE] = {0};
  struct cmsghdr *cmsg; // Pointer to control message

  if(m_SocketFd < 0) {
    CDM_DLOG() << "Invalid socket file descriptor";
    status = -1;
	goto handle_error;
  }

  /* Send buffer size with the file descriptor */
  iov.iov_base = &f_Size;
  iov.iov_len  = sizeof(f_Size);

  msg.msg_name       = NULL;
  msg.msg_namelen    = 0;
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = cmsg_buffer;
  msg.msg_controllen = CMSG_SIZE;
  msg.msg_flags      = 0; /* ignored */

  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_SIZE;
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  *(int *)CMSG_DATA(cmsg) = f_FileDescriptor;

  if(f_FileDescriptor < 0) {
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
  }

  status = sendmsg(m_SocketFd, &msg, 0);
  if(status >= 0) {
    status = 0;  // Success
  } else {
    if(errno == EWOULDBLOCK || errno == EAGAIN)
      CDM_DLOG() << "Cannot send FD (Timeout)";
    else
      CDM_DLOG() << "Cannot send FD";
	goto handle_error;
  }

handle_error:
  return status;
}

}  // namespace WPEFramework
