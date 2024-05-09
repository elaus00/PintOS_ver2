#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);

// static int wait (pid_t);
static pid_t exec (const char *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int *p = f->esp;
  if(!is_valid_ptr(p)){
    exit(-1);
  }
  int syscall_number = *p;
  switch (syscall_number)
  {
  case SYS_EXIT:
  int status=*p+1;
  sys_exit(status);
    break;
  case SYS_HALT:
    f->eax=1;
    break;

  default:
    break;
  }
  
printf ("system call!\n");

  // thread_exit ();
}

bool is_valid_ptr (const void *usr_ptr){
  struct thread *cur = thread_current();
  ASSERT(!usr_ptr);
  is_user_vaddr(usr_ptr);
  void *uaddr = pagedir_get_page(cur->pagedir, usr_ptr);
  ASSERT(!uaddr);
}

pid_t exec(const char *cmd_line){
  struct thread *cur= thread_current();
  tid_t tid =cur->tid;
  if(!is_valid_ptr(cmd_line)){
    exit(-1);
  }
  else{
    // int *childstatus =&(cur->child_load_status);
  cur->child_load_status=0;
  tid=process_execute(cmd_line);
  // struct lock *child = &(cur->lock_child);
  lock_acquire(&cur->lock_child);
  cond_wait(&cur->child_load_status,&cur->lock_child);
  
  if(cur->child_load_status==-1){
    tid=-1;
  }
  lock_release(cur->lock_child);
  }
  return tid;
}

