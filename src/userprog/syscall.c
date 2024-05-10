#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"

static pid_t exec (const char *);
static void halt (void);
static void exit (int);
static int write (int, const void *, unsigned);

static void syscall_handler(struct intr_frame *);

struct lock fs_lock;

struct list open_files; 

struct file_descriptor
{
  int fd_num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};

static struct file_descriptor *get_open_file (int);

static uint32_t *esp;



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
  list_init (&open_files);
  lock_init (&fs_lock);
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  esp = (uint32_t *)f->esp;
  if (!is_valid_ptr(esp))
  {
    // printf("valid");
    exit(-1);
  }
  switch (*esp)
  {
  case SYS_EXIT:
  {
    // printf("exit!\n");
    int status = *(esp + 1);
    exit(status);
    break;
  }
  case SYS_HALT:
    halt();
    break;

  
  // case SYS_WRITE:
  // // printf("write!\n");
  //  f->eax = write (*(esp + 1), (void *) *(esp + 2), *(esp + 3));
  //  break;

  case SYS_EXEC:
  printf("execute!\n");
  f->eax = exec ((char *) *(esp + 1));
  break;

  default:
  // printf("%dno system call!\n", *esp);
    break;
  }

  

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

int
write (int fd, const void *buffer, unsigned size)
{
  struct file_descriptor *fd_struct;  
  int status = 0;

  unsigned buffer_size = size;
  void *buffer_tmp = buffer;

  /* check the user memory pointing by buffer are valid */
  while (buffer_tmp != NULL)
    {
      if (!is_valid_ptr (buffer_tmp)){
	exit (-1);
      }
      
      /* Advance */ 
      if (buffer_size > PGSIZE)
	{
	  buffer_tmp += PGSIZE;
	  buffer_size -= PGSIZE;
	}
      else if (buffer_size == 0)
	{
	  /* terminate the checking loop 지금 여기있음 */
	  buffer_tmp = NULL;
	}
      else
	{
	  /* last loop */
	  buffer_tmp = buffer + size - 1;
	  buffer_size = 0;
	}
    }
  lock_acquire (&fs_lock); 
  if (fd == 0)
    {
      
      status = -1;
    }
  else if (fd == 0)
    {
      
      putbuf (buffer, size);;
      status = size;
    }
  else 
    {
      //지금 여기//
      fd_struct = get_open_file (fd);
      if (fd_struct != NULL){
	status = file_write (fd_struct->file_struct, buffer, size);
  printf("wowow");
      }
    }
  lock_release (&fs_lock);
  return status;
}

struct file_descriptor *
get_open_file (int fd)
{
  
  struct list_elem *e;
  struct file_descriptor *fd_struct; 
  e = list_tail (&open_files);
  while ((e = list_prev (e)) != list_head (&open_files)) 
    {
      printf("work?");
      fd_struct = list_entry (e, struct file_descriptor, elem);
      if (fd_struct->fd_num == fd)
	return fd_struct;
    }
  return NULL;
}
