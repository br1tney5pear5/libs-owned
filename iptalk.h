/* 
 *
 *
 * This library aims to minimise mental overhead of 
 * making different processes talk to each other (IPC).
 * whether its on the same system or over the network.  *
 *
 * Rationale
 *
 *   IPC is always boilerplate chore and sometimes source 
 *   of subtle bugs like say you have an edge case where 
 *   your program will block forever. Or your protocol
 *   is datagram based but you realise that the maximum
 *   datagram size isn't enough for you. So you either
 *   implement segmentation/reassembly or convert it to
 *   stream and assure message boundaries yourself.
 *   That's what just comes up to mind rt.
 *
 *   So the point of this library is not to be some a 
 *   glorified socket wrapper or some fancy asynchronous
 *   webserver grade networking. Instead the goal is 
 *   a simple interface for a simple thing - talking to 
 *   other programs. Goal is to be write communication 
 *   between two programs in 5 minutes and be done with it.
 *
 *
 * Ancillary goals
 *
 *   [ ] Be poll-driven. You find in system engineering 
 *       many daemon program will be based on a central
 *       loop monitoring file descriptors with something
 *       like epoll. This library should integrate with 
 *       this paradigm.
 *
 *   [ ] Support UNIX sockets for programs talking to 
 *       each other on the same system.
 *
 *   [ ] Support INET sockets for programs talking to 
 *       each other over the network.
 *
 * */
#ifndef _IPTALK_H_
#define _IPTALK_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

/* TODO: explain */
#undef unix

struct iptalk_list_head;
struct iptalk_config;
struct iptalk_header;
struct iptalk_buffer;
struct iptalk_header;
struct iptalk;
struct iptalk_event;

enum {
  IPTALK_INVALID = 0,
  IPTALK_UNIX,
};

struct iptalk_list_head {
  struct iptalk_list_head *next;
  struct iptalk_list_head *prev;
};

#define iptalk_list_for(POS, HEAD)\
  for(struct iptalk_list_head *POS = (HEAD)->next;\
      (POS) != (HEAD);\
      POS = (POS)->next)

#define iptalk_list_safe_for(POS, HEAD)\
  for (struct iptalk_list_head *POS = (HEAD)->next, *__next = (POS)->next;\
      (POS) != (HEAD);\
       POS = __next, __next = (POS)->next)

#define iptalk_list_empty(LIST) ((LIST)->next == (LIST)->prev)


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

struct iptalk_buffer {
  struct iptalk_list_head list;
  struct iptalk_convo *convo;
  void *data;
  size_t offset;
  size_t size;
  struct iptalk_header *header;
};

struct iptalk_convo {
  struct iptalk_list_head list;
  struct iptalk *iptalk;
  int sock;

  uint8_t flags;

  struct iptalk_buffer *current_buffer;
  struct iptalk_list_head buffers;
  
  void *user_data;
};

struct iptalk {
  int epoll_sock;
  int sock;

  /* Only filled on for the client, server doesn't have a
   * main convo */
  struct iptalk_convo *main_convo;

  struct iptalk_list_head convos;
  struct iptalk_list_head events;

  union {
    struct {
      struct sockaddr_un local; 
      struct sockaddr_un remote; 
      char tempfile[64];
    } unix;
  };
  struct iptalk_config config;
};


#define IPTALK_MESSAGE_MAGIC 0xbeef

struct iptalk_header {
  uint16_t magic;   /* Basic protection against bugs in this code really */
  uint8_t version;  /* Version in case we want to add something to this 
                     * header in the future */
  uint8_t flags;    /* Miscellaneous internal flags */
  uint32_t pad[2];  /* Pad space for new fields */
  uint32_t size;    /* Size of this message (including this header) */
  char data[];      /* The actual user provided data */
} __attribute__((packed));


#define _BIT(N) (1 << (N))
enum {
  IPTALK_EVENT_INVALID              = 0,
  IPTALK_EVENT_CONVO_STARTED        = _BIT(0),
  IPTALK_EVENT_CONVO_ENDED          = _BIT(1),
  IPTALK_EVENT_MESSAGE_RECEIVED     = _BIT(2),
};

struct iptalk_event {
  struct iptalk_list_head list;
  struct iptalk *iptalk;
  int type;
  union {
    void *data;
    struct iptalk_convo *convo;
    struct iptalk_buffer *buffer;
  };
};

#define foreach_iptalk_event(EVENT, IPTALK)\
  for(struct iptalk_event *EVENT = next_iptalk_event(IPTALK, NULL);\
      EVENT; EVENT = next_iptalk_event(IPTALK, EVENT))

/* Create a new iptalk instance
 */
struct iptalk *new_iptalk(struct iptalk_config *config);

/* Delete and clean-up after an iptalk instance 
 */
void del_iptalk(struct iptalk *ipt);

/* Send message over iptalk (XXX: semantics might change)
 */
ssize_t iptalk_sendmsg(struct iptalk_convo *convo, void *data, size_t len);

/* 
 */
struct iptalk_event *next_iptalk_event(
    struct iptalk *iptalk, struct iptalk_event *event);

/* Delete handled iptalk event 
 */
void del_iptalk_event(struct iptalk_event *event);

/* Gather events basically
 */
int iptalk_tick(struct iptalk *iptalk);

#endif /* _IPTALK_H_ */

/*
 *
 * Implementation
 *
 */

#ifdef IPTALK_IMPLEMENTATION
#ifndef _IPTALK_H_IMPL_
#define _IPTALK_H_IMPL_

#include <sys/epoll.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <endian.h>
#include <time.h>

/* You can overwrite IPTALK_XALLOC to implement a custom allocator 
 */
#ifndef IPTALK_XALLOC
int free_count = 0;
int alloc_count = 0;
static inline void *_default_iptalk_xalloc(void *ptr, size_t sz)
{ return (!sz ? (free(ptr), free_count++, NULL) : (!ptr ? (alloc_count++, malloc(sz)) : realloc(ptr, sz))); }
#define IPTALK_XALLOC(PTR, SZ) _default_iptalk_xalloc(PTR, SZ)
#endif

#define IPTALK_DEBUG_PRINT(...)\
  do {\
    fprintf(stderr, "%s:%d: ", __func__, __LINE__);\
    fprintf(stderr, __VA_ARGS__);\
    fprintf(stderr, "\n");\
  } while(0)

struct iptalk_buffer *new_iptalk_buffer();
void del_iptalk_buffer(struct iptalk_buffer *buffer);

struct iptalk_event *new_iptalk_event(
    struct iptalk *iptalk, int type, void * data);
void del_iptalk_event(struct iptalk_event *event);

struct iptalk_convo *new_iptalk_convo(struct iptalk *iptalk);
void del_iptalk_convo(struct iptalk_convo *convo);

/*
 * IPTALK List
 */

static inline 
void iptalk_list_init(struct iptalk_list_head *list)
{
  list->next = list->prev = list;
}

static inline
void iptalk_list_add(struct iptalk_list_head *new, struct iptalk_list_head *head) 
{
  head->prev->next = new;
  new->prev = head->prev;
  new->next = head;
  head->prev = new;
}

static inline
void iptalk_list_del(struct iptalk_list_head *entry)
{
  entry->next->prev = entry->prev;
  entry->prev->next = entry->next;
  entry->prev = entry->next = entry;
}


/* 
 * IPTALK Buffer
 */

struct iptalk_buffer *new_iptalk_buffer() 
{
  struct iptalk_buffer *buffer = 
    IPTALK_XALLOC(NULL, sizeof(struct iptalk_buffer));
  memset(buffer, 0, sizeof(*buffer));

  return buffer;
}

void del_iptalk_buffer(struct iptalk_buffer *buffer)
{
  if(buffer->list.next)
    iptalk_list_del(&buffer->list);
  if(buffer->data)
    buffer->data = IPTALK_XALLOC(buffer->data, 0);
  buffer = IPTALK_XALLOC(buffer, 0);
}

int realloc_iptalk_buffer(struct iptalk_buffer *buffer, size_t new_size)
{
  /* TODO: Can't go bigger than UINT32_MAX */
  if(new_size <= buffer->size)
    return 0;
  buffer->size = new_size;
  buffer->data = IPTALK_XALLOC(buffer->data, buffer->size);
  /* TODO: error handle */
  assert(buffer->data);
  return 0;
}

ssize_t append_to_iptalk_buffer(
    struct iptalk_buffer *buffer, const void *data, size_t size)
{
  realloc_iptalk_buffer(buffer, buffer->offset + size);
  memcpy(buffer->data + buffer->offset, data, size);
  buffer->offset += size;
  assert(buffer->offset <= buffer->size);
  return size;
}

ssize_t recv_to_iptalk_buffer(
    struct iptalk_buffer *buffer, int sock, size_t n)
{
  realloc_iptalk_buffer(buffer, buffer->offset + n);
  size_t left = buffer->size - buffer->offset;
  assert(left >= n);
  ssize_t received =  recv(sock, buffer->data + buffer->offset, n, 0);
  if(received > 0) {
    buffer->offset += received;
  }
  return received;
}

/*
 * IPTALK Event
 */

struct iptalk_event *new_iptalk_event(
    struct iptalk *iptalk, int type, void * data) 
{
  /* TODO: validate */
  struct iptalk_event *event = 
    IPTALK_XALLOC(NULL, sizeof(struct iptalk_event));
  memset(event, 0, sizeof(*event));
  event->iptalk = iptalk;
  event->type = type;
  event->data = data;
  assert(event);
  iptalk_list_add(&event->list, &iptalk->events);
  return event;
}

void del_iptalk_event(struct iptalk_event *event)
{
  if(event->list.next)
    iptalk_list_del(&event->list);

  switch(event->type) { 
    case IPTALK_EVENT_CONVO_STARTED:
      break;
    case IPTALK_EVENT_CONVO_ENDED:
      del_iptalk_convo(event->convo);
      break;
    case IPTALK_EVENT_MESSAGE_RECEIVED:
      del_iptalk_buffer(event->buffer);
      break;
    default:
      fprintf(stderr, "Could not clean-up invalid event type (%d)", 
          event->type);
  }
  event = IPTALK_XALLOC(event, 0);
}

/*
 * IPTALK Convo
 */

struct iptalk_convo *new_iptalk_convo(struct iptalk *ipt)
{
  struct iptalk_convo *convo = IPTALK_XALLOC(NULL, sizeof(struct iptalk_convo));
  assert(convo);
  memset(convo, 0, sizeof(*convo));
  iptalk_list_add(&convo->list, &ipt->convos);
  convo->iptalk = ipt;
  iptalk_list_init(&convo->buffers);
  new_iptalk_event(convo->iptalk, IPTALK_EVENT_CONVO_STARTED, convo);
  return convo;
}

struct iptalk_convo *find_iptalk_convo(struct iptalk *ipt, int sock)
{
  iptalk_list_for(convo_ent, &ipt->convos) {
    /* TODO use container_of */
    struct iptalk_convo *convo = (void*)convo_ent;
    if(convo->sock < 0)
      continue;
    if(convo->sock == sock)
      return convo;
  }
  return NULL;
}

void close_iptalk_convo(struct iptalk_convo *convo)
{
  IPTALK_DEBUG_PRINT("Close iptalk convo %p\n", convo);
  struct iptalk *ipt = convo->iptalk;
  if(epoll_ctl(ipt->epoll_sock, EPOLL_CTL_DEL, convo->sock, NULL)) {
    perror("epoll_ctl()");
  }
  if(close(convo->sock)) {
    perror("close()");
  }
  convo->sock = -1;
  new_iptalk_event(convo->iptalk, IPTALK_EVENT_CONVO_ENDED, convo);
}

int discard_iptalk_convo_buffer(struct iptalk_convo *convo)
{
  if(!convo->current_buffer)
    return -1;
  del_iptalk_buffer(convo->current_buffer);
  return 0;
}
void del_iptalk_convo(struct iptalk_convo *convo) {
  if(convo->sock >= 0) {
    close_iptalk_convo(convo);
  }

  discard_iptalk_convo_buffer(convo);
  iptalk_list_safe_for(buffer_ent, &convo->buffers)
    del_iptalk_buffer((struct iptalk_buffer*)buffer_ent);

  if(convo->list.next)
    iptalk_list_del(&convo->list);
  IPTALK_XALLOC(convo, 0);
}

struct iptalk_buffer * get_iptalk_convo_buffer(struct iptalk_convo *convo)
{
  if(!convo->current_buffer) {
    convo->current_buffer = new_iptalk_buffer();
    convo->current_buffer->convo = convo;
  }
  return convo->current_buffer;
}

int commit_iptalk_convo_buffer(struct iptalk_convo *convo)
{
  /* TODO sanity check the buffer */
  struct iptalk_buffer *buffer = convo->current_buffer;
  convo->current_buffer = NULL;
  iptalk_list_add(&buffer->list, &convo->buffers);
  new_iptalk_event(convo->iptalk, IPTALK_EVENT_MESSAGE_RECEIVED, buffer);
  return 0;
}


int parse_iptalk_convo_buffer(struct iptalk_convo *convo) 
{
  int ret = -1;
  struct iptalk_buffer *buffer = NULL;
again:
  buffer = get_iptalk_convo_buffer(convo);
  /* Parse buffer header if it hasn't been parsed yet 
   */
  if(!buffer->header && buffer->offset >= sizeof(*buffer->header)) {
    buffer->header = (struct iptalk_header*)buffer->data;

    if(be16toh(buffer->header->magic) != IPTALK_MESSAGE_MAGIC) {
      fprintf(stderr, "Bad magic\n");
      discard_iptalk_convo_buffer(convo);
      goto out;
    }
    if(buffer->header->version != 1) {
      fprintf(stderr, "Unsupported version\n");
      discard_iptalk_convo_buffer(convo);
      goto out;
    }
  }

  /* Have we got the full message?
   */
  buffer->header = (struct iptalk_header*)buffer->data;
  if(buffer->offset >= buffer->header->size) {
    if(!buffer->header) {
      fprintf(stderr, "Invalid message\n");
      goto out;
    }
    commit_iptalk_convo_buffer(convo);
    int remainder = buffer->offset - buffer->header->size;
    if(remainder) {
      struct iptalk_buffer *new_buffer = get_iptalk_convo_buffer(convo);
      assert(new_buffer != buffer);
      append_to_iptalk_buffer(new_buffer, 
          buffer->data + buffer->header->size, remainder);
      goto again;
    }
  }
  ret = 0;
out:
  return ret;
}

int get_iptalk_socket(struct iptalk *ipt)
{
  return ipt->epoll_sock;
}

struct iptalk_event *next_iptalk_event(
    struct iptalk *iptalk, struct iptalk_event *event)
{
  if(event) {
    if((void*)event->list.next != &iptalk->events) {
      assert(event->list.next);
      return (struct iptalk_event*)event->list.next;
    }
  } else {
    if(iptalk->events.prev != &iptalk->events) {
      return (struct iptalk_event*)iptalk->events.next;
    }
  }
  return NULL;
}

int _init_unix_iptalk_client(struct iptalk *ipt)
{
  int ret = -1;

  ipt->sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if(ipt->sock < 0) {
    perror("socket()");
    goto out;
  }

  char tempfile[] = "/tmp/iptalk.XXXXXX";
  int tempfd = -1;
  if((tempfd = mkstemp(tempfile)) < 0) {
    perror("mkstemp()");
    goto out;
  } else {
    close(tempfd);
  }
  /* TODO: make safe */
  strcpy(ipt->unix.tempfile, tempfile);

  ipt->unix.local.sun_family = AF_UNIX;
  unlink(tempfile);
  strcpy(ipt->unix.local.sun_path, tempfile);

  ipt->unix.remote.sun_family = AF_UNIX;
  strcpy(ipt->unix.remote.sun_path, ipt->config.unix.filename);

  if(bind(ipt->sock, 
          (struct sockaddr*)&ipt->unix.local, 
          sizeof(ipt->unix.local))) 
  {
    perror("bind()");
    goto out;
  }

  if(connect(ipt->sock, 
        (struct sockaddr*)&ipt->unix.remote, 
        sizeof(ipt->unix.remote)))
  {
    perror("connect()");
    goto out;
  }

  ipt->main_convo = new_iptalk_convo(ipt);
  ipt->main_convo->sock = ipt->sock;

  ret = 0;
out:
  return ret;
}


int _init_unix_iptalk_server(struct iptalk *ipt)
{
  int ret = -1;
  /* Because we are connection oriented server we will accept end up with
   * one listening socket and possibly multiple connection sockets.
   *
   * Now lets say that the user wants to poll on us, what do we do?
   * TODO: finish
   */
  ipt->sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if(ipt->sock < 0) {
    perror("socket()");
    goto out;
  }

  ipt->unix.local.sun_family = AF_UNIX;
  /* TODO: Make sure the name isn't too long */
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
  IPTALK_DEBUG_PRINT("ipt=%p sock=%d epoll_sock=%d local='%s'", 
      ipt, ipt->epoll_sock, ipt->sock, ipt->unix.local.sun_path);

  ret = 0;
out:
  return ret;
}



void del_iptalk(struct iptalk *iptalk) 
{
  if(iptalk->epoll_sock >= 0)
    iptalk->epoll_sock = (close(iptalk->epoll_sock), -1);

  if(iptalk->sock >= 0)
    iptalk->sock = (close(iptalk->sock), -1);

  iptalk_list_safe_for(convo_ent, &iptalk->convos)
    del_iptalk_convo((struct iptalk_convo*)convo_ent);

  iptalk_list_safe_for(event_ent, &iptalk->events)
    del_iptalk_event((struct iptalk_event*)event_ent);

  if(iptalk->config.type == IPTALK_UNIX) {
    if(iptalk->unix.tempfile[0]) {
      unlink(iptalk->unix.tempfile);
    }
  }
  /* Invalidate as much as possible */
  memset(iptalk, 0, sizeof(*iptalk));
  iptalk->sock = -1;
  iptalk->epoll_sock = -1;

  IPTALK_XALLOC(iptalk, 0);
}

struct iptalk *new_iptalk(struct iptalk_config *config)
{
  struct iptalk *ipt = IPTALK_XALLOC(NULL, sizeof(struct iptalk));
  if(!ipt)
    return NULL;
  
  ipt->config = *config;
  iptalk_list_init(&ipt->convos);
  iptalk_list_init(&ipt->events);

  ipt->epoll_sock = epoll_create(1);
  IPTALK_DEBUG_PRINT("epoll_sock=%d", ipt->epoll_sock);
  if(ipt->epoll_sock < 0) {
    perror("epoll_create()");
    goto err;
  }

  switch(ipt->config.type) {
    case IPTALK_UNIX:
      if(ipt->config.unix.server) {
        if(_init_unix_iptalk_server(ipt))
          goto err;
      } else {
        if(_init_unix_iptalk_client(ipt))
          goto err;
      }
      break;
    default:
      goto err;
  }

  struct epoll_event event = {
    .events = EPOLLIN,
    .data = { .fd = ipt->sock, }
  };
  if(epoll_ctl(ipt->epoll_sock, EPOLL_CTL_ADD, ipt->sock, &event)) {
    perror("epoll_ctl()");
    goto err;
  }

  IPTALK_DEBUG_PRINT("ipt=%p", ipt);
  return ipt;
err:
  return (del_iptalk(ipt), NULL);
}

#define IPTALK_MAX_EVENTS 128

int iptalk_wait(struct iptalk *iptalk, int timeout)
{
  struct epoll_event epoll_event = {0};
  int rc = epoll_wait(iptalk->epoll_sock, &epoll_event, 1, timeout);
  iptalk_tick(iptalk);
  return rc;
}


long int _time_now()
{
  struct timespec time = {0};
  clock_gettime(CLOCK_MONOTONIC, &time);
  long int result =  time.tv_sec * 1000 + time.tv_nsec / (1000000LL);
  printf("%ld %ld %ld\n", time.tv_sec, time.tv_nsec, result);
  return time.tv_sec * 1000 + time.tv_nsec / (1000000LL);
}

int iptalk_wait_for(struct iptalk *iptalk, int timeout, uint32_t mask)
{
  long int deadline = _time_now() + timeout;
  while(true) {
    long int left = deadline - _time_now();
    IPTALK_DEBUG_PRINT("left=%ld", left);
    if(left <= 0) break;
    iptalk_wait(iptalk, left);
    foreach_iptalk_event(event, iptalk) {
      if(event->type & mask)
        return 0;
    }
  }
  return -1;
}

int iptalk_tick(struct iptalk *iptalk)
{
  IPTALK_DEBUG_PRINT("ALLOC=%d FREE=%d DIFF=%d", 
      alloc_count, free_count, alloc_count - free_count);
  int ret = -1;
  /* If there are some unhandled events from the previous tick
   * delete all of them.
   *
   * TODO: Should have a separate wrapper function
   *       for user that marks this event as handled. 
   *       If it isn't (we used our internal function
   *       here) we should warn the user that an event
   *       went unhandled in some super verbose mode.
   */
  iptalk_list_safe_for(event_ent, &iptalk->events)
    del_iptalk_event((struct iptalk_event*)event_ent);

  assert(iptalk_list_empty(&iptalk->events));

  struct epoll_event events[IPTALK_MAX_EVENTS];
  int num_events = epoll_wait(iptalk->epoll_sock, events, IPTALK_MAX_EVENTS, 0);
  IPTALK_DEBUG_PRINT("sock=%d num_events=%d\n", iptalk->epoll_sock, num_events);
  if(num_events < 0) {
    perror("epoll_wait()");
    goto out; 
  }

  for(int i = 0; i < num_events; ++i) {
    printf("epoll event fd=%d flags=%d\n", events[i].data.fd, events[i].events);
    struct iptalk_convo *convo = NULL;
    /* If we are a server and the socket is the listening socket
     * try accept a new connection */
    if(iptalk->config.unix.server && events[i].data.fd == iptalk->sock) {
      convo = new_iptalk_convo(iptalk);
      /* TODO: get the peer address into convo */
      convo->sock = accept(iptalk->sock, NULL, NULL);
      if(convo->sock < 0) {
        perror("accept()");
        goto out;
      }

      struct epoll_event event = {
        .events = EPOLLIN,
        .data = { .fd = convo->sock, }
      };
      if(epoll_ctl(iptalk->epoll_sock, EPOLL_CTL_ADD, convo->sock, &event)) {
        perror("epoll_ctl()");
        goto out;
      }
      continue ;
    }

    if(events[i].events & EPOLLIN) {
      convo = find_iptalk_convo(iptalk, events[i].data.fd);
      if(!convo) {
        fprintf(stderr, "No conversation.\n");
        continue;
      }
      struct iptalk_buffer *buffer = get_iptalk_convo_buffer(convo);

      ssize_t received = recv_to_iptalk_buffer(buffer, convo->sock, 2048);
      if(received < 0) {
        perror("recv()");
        continue;
      }

      //IPTALK_DEBUG_PRINT("Receive %d buf=%p offset=%d", 
      //              received, buffer, buffer->offset);
      if(received == 0) {
        /* Convo ended */
        close_iptalk_convo(convo);
        continue;
      }
      
      if(parse_iptalk_convo_buffer(convo)) {
        fprintf(stderr, "Failed to parse the message.");
        continue;
      }
    }
  }

  ret = 0;
out:
  return ret;
}

ssize_t iptalk_sendmsg(struct iptalk_convo *convo, void *data, size_t len)
{
  ssize_t rc = -1;
  /* TODO: check size against max uint32 */
  struct iptalk_header header = {
    .magic = htobe16(IPTALK_MESSAGE_MAGIC),
    .version = 1,
    .flags = 0,
    .size = sizeof(header) + len,
  };
  rc = send(convo->sock, &header, sizeof(header), 0);
  if(rc != sizeof(header))
    return -1;

  rc = send(convo->sock, data, len, 0);
  if(rc != sizeof(len))
    return -1;

  return 0;
}

#endif /* _IPTALK_H_IMPL_ */
#endif /* IPTALK_IMPLEMENTATION */

