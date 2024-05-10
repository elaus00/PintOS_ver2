#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
typedef int pid_t;

static void syscall_handler (struct intr_frame *);

bool is_valid_ptr(const void *usr_ptr)
{
  struct thread *cur = thread_current();
  ASSERT(!usr_ptr);
  is_user_vaddr(usr_ptr);
  void *uaddr = pagedir_get_page(cur->pagedir, usr_ptr);
  ASSERT(!uaddr);
}

// static int wait (pid_t);
// static pid_t exec (const char *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  int *p = f->esp;
  if (!is_valid_ptr(p))
  {
    exit(-1);
  }
  switch (*p)
  {
  case SYS_EXIT:{
    int status = *(p + 1);
    exit(status);
    break;
  }
  case SYS_WAIT:{
    int status= *(p + 1);
    f->eax = wait(status);
    break;
  }
  // case SYS_EXEC:
  //   int status= *(p + 1);
  //   f->eax = exec((char*) status);
  //   break;
  case SYS_HALT:
    halt();
    break;

  default:
    break;
  }

  printf("system call!\n");

  // thread_exit ();
}



int wait(pid_t pid){
  return process_wait(pid);
}

pid_t exec(const char *cmd_line)
{
  struct thread *cur = thread_current();
  tid_t tid = cur->tid;
  if (!is_valid_ptr(cmd_line))
  {
    exit(-1);
  }
  else
  {
    cur->child_load_status = 0;
    tid = process_execute(cmd_line);
    lock_acquire(&cur->lock_child);
    cond_wait(&cur->child_load_status, &cur->lock_child);

    if (cur->child_load_status == -1)
    {
      tid = -1;
    }
    lock_release(cur->lock_child);
  }
  return tid;
}


void halt(){
  shutdown_power_off();
}