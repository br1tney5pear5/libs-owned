/* The purpose of this library 
 *
 *
 *
 *
 *
 *
 * */
#ifndef _IPTALK_H_
#define _IPTALK_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

/* TODO: explain */
#undef unix

enum {
  IPTALK_INVALID = 0,
  IPTALK_UNIX,
};

struct iptalk_config {
  int type;

  /* type specific configs */
  union {
    struct {
      bool server;
      const char *filename;
    } unix;
  };
  /* only applies to servers */
  int backlog;
};

struct iptalk_convo {
  int sock;

  size_t buffer_size;
  size_t buffer_offset;
  void *buffer;
};

struct iptalk {
  int epoll_sock;
  int sock;

  int num_convos;
  struct iptalk_convo *convos;

  union {
    struct {
      struct sockaddr_un local; 
      struct sockaddr_un remote; 
    } unix;
  };
  struct iptalk_config config;
};


#define IPTALK_MESSAGE_MAGIC 0xbeef

struct iptalk_message {
  uint16_t magic;
  uint8_t version;
  uint8_t flags;
  uint32_t pad[2];
  uint32_t size;
  char data[];
} __attribute__((packed));

struct iptalk *new_iptalk(struct iptalk_config *config);
void del_iptalk(struct iptalk *ipt);

int iptalk_send(void *data, int len);
int iptalk_recv(void *data, int len);

#ifndef IPTALK_XALLOC
static inline void *_default_iptalk_xalloc(void *ptr, size_t sz)
{ return (!sz ? (free(ptr), NULL) : (!ptr ? malloc(sz) : realloc(ptr, sz))); }
#define IPTALK_XALLOC(PTR, SZ) _default_iptalk_xalloc(PTR, SZ)
#endif

struct iptalk_convo *new_iptalk_convo(struct iptalk *ipt)
{
  ipt->num_convos += 1;
  int sz = (ipt->num_convos * sizeof(struct iptalk_convo));
  ipt->convos = IPTALK_XALLOC(ipt->convos, sz);
  assert(ipt->convos);
  return &ipt->convos[ipt->num_convos - 1];
}

struct iptalk_convo *find_iptalk_convo_by_socket(struct iptalk *ipt, int sock)
{
  for(int i = 0; i < ipt->num_convos; ++i) {
    if(ipt->convo[i].sock == sock)
      return &ipt->convo[i];
  }
  return NULL;
}

int get_iptalk_socket(struct iptalk *ipt)
{
  return ipt->epoll_sock;
}


int _init_unix_iptalk(struct iptalk *ipt)
{
  int ret = -1;

  if(ipt->config.unix.server) {
    /* Because we are connection oriented server we will accept end up with
     * one listening socket and possibly multiple connection sockets.
     *
     * Now lets say that the user wants to poll on us, what do we do?
     * TODO: finish
     */

    ipt->epoll_sock = epoll_create(1);
    if(ipt->epoll_sock < 0) {
      perror("epoll_create()");
      goto out;
    }

    ipt->sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if(ipt->sock < 0) {
      perror("socket()");
      goto out;
    }

    ipt->unix.local.sun_family = AF_UNIX;
    unlink(ipt->config.unix.filename);
    strcpy(ipt->unix.local.sun_path, ipt->config.unix.filename);

    if(bind(ipt->sock, 
          (struct sockaddr*)&ipt->unix.local, 
          sizeof(ipt->unix.local))) 
    {
      perror("bind()");
      goto out;
    }

    /* TODO: use config.backlog */
    if(listen(ipt->sock, 10)) {
      perror("listen()");
      goto out;
    }

    int flags = fcntl(ipt->sock, F_GETFL, 0);
    if(flags < 0 || fcntl(ipt->sock, F_SETFL, flags | O_NONBLOCK)) {
      perror("fcntl()");
      goto out;
    }

    struct epoll_event event = {
      .events = EPOLLIN,
      .data = { .fd = ipt->sock, }
    };
    if(epoll_ctl(ipt->epoll_sock, EPOLL_CTL_ADD, ipt->sock, &event)) {
      perror("epoll_ctl()");
      goto out;
    }
  } else {
    assert(0);
  }

  ret = 0;
out:
  return ret;
}

struct iptalk *new_iptalk(struct iptalk_config *config)
{
  struct iptalk *ipt = IPTALK_XALLOC(NULL, sizeof(struct iptalk));
  if(!ipt)
    return NULL;

  ipt->config = *config;

  switch(ipt->config.type) {
    case IPTALK_UNIX:
      if(_init_unix_iptalk(ipt))
        goto err;
      break;
    default:
      goto err;
  }

  return ipt;
err:
  return IPTALK_XALLOC(ipt, 0);
}

#define IPTALK_MAX_EVENTS 128

int iptalk_tick(struct iptalk *ipt)
{
  int ret = -1;

  struct epoll_event events[IPTALK_MAX_EVENTS];
  int num_events = epoll_wait(ipt->epoll_sock, events, IPTALK_MAX_EVENTS, 0);
  printf("num_events=%d\n", num_events);
  if(num_events < 0) {
    perror("epoll_wait()");
    goto out; 
  }

  for(int i = 0; i < num_events; ++i) {
    /* If we are a server and the socket is the listening socket
     * try accept a new connection */
    if(ipt->config.unix.server && events[i].data.fd == ipt->sock) {
      struct iptalk_convo *convo = new_iptalk_convo(ipt);
      /* TODO: get the peer address into convo */
      convo->sock = accept(ipt->sock, NULL, NULL);
      if(convo->sock < 0) {
        perror("accept()");
        goto out;
      }

      struct epoll_event event = {
        .events = EPOLLIN,
        .data = { .fd = convo->sock, }
      };
      if(epoll_ctl(ipt->epoll_sock, EPOLL_CTL_ADD, convo->sock, &event)) {
        perror("epoll_ctl()");
        goto out;
      }

      printf("New convo %d\n", convo->sock);
      continue;
    }


    printf("%d readable\n", events[i].data.fd);
  }

  ret = 0;
out:
  return ret;
}

#endif /* _IPTALK_H_ */

