#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"

static pid_t exec (const char *);
static void halt (void);
static void exit (int);

static void syscall_handler(struct intr_frame *);

bool is_valid_ptr(const void *usr_ptr)
{
  struct thread *cur = thread_current();
  if (usr_ptr == NULL || !is_user_vaddr(usr_ptr)) {
    return false;
  }
  void *uaddr = pagedir_get_page(cur->pagedir, usr_ptr);
  return uaddr != NULL;
}

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  int *p = (int *)f->esp;
  if (!is_valid_ptr(p))
  {
    exit(-1);
  }
  int syscall_number = *p;
  switch (syscall_number)
  {
  case SYS_EXIT:
  {
    int status = *(p + 1);
    exit(status);
    break;
  }
  case SYS_HALT:
    halt();
    break;

  default:
    break;
  }

  printf("system call!\n");

  // thread_exit ();
}

pid_t
exec(const char *cmd_line)
{
  struct thread *cur = thread_current();
  tid_t tid = NULL;
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

int wait(pid_t pid){
  return process_wait(pid);
}

void exit(int status)
{
  struct thread *cur = thread_current();
  struct thread *parent = thread_get_by_id(&cur->parent_id);

  // parent thread가 존재할 경우, current thread를 찾기 위해 children list를 검색한다.
  if (parent)
  {
    struct list_elem *e;
    struct child_status *child = NULL;

    for (e = list_begin(&parent->children); e != list_end(&parent->children); e = list_next(e))
    {
      child = list_entry(e, struct child_status, elem_child_status);
      // parent_list에 있는 특정 child의 id가 현재 실행중인 스레드의 id 값이라면 exit한다.
      if (child->child_id == cur->tid)
      {
        lock_acquire(&parent->lock_child);
        child->is_exit_called = true;
        child->child_exit_status = status;
        lock_release(&parent->lock_child);
        break;
      }
    }
    thread_exit();
  }
}

void halt(void)
{
  shutdown_power_off();
}
