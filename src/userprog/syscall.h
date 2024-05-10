#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "userprog/process.h"

typedef int pid_t;

void syscall_init (void);
bool is_valid_ptr (const void *);

#endif /* userprog/syscall.h */
