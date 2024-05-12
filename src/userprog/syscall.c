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
#include "filesys/file.h"
#include "devices/input.h"
#include "filesys/filesys.h"

static pid_t exec(const char *);
static void halt(void);
static void exit(int);
static int write(int, const void *, unsigned);
void close_file_by_owner (tid_t tid);
bool create(const char *file, unsigned initial_size);
static void syscall_handler(struct intr_frame *);
int open(const char *file_name);
static int allocate_fd (void);
bool remove(const char *file_name);
int filesize(int fd);
// void close(int fd);
// unsigned tell(int fd);
void seek(int fd, unsigned position);

struct lock fs_lock;

struct list open_files;

struct file_descriptor
{
  int fd_num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};

static struct file_descriptor *get_open_file(int);

static uint32_t *esp;

bool is_valid_ptr(const void *usr_ptr)
{
  struct thread *cur = thread_current();
  if (usr_ptr == NULL || !is_user_vaddr(usr_ptr))
  {
    return false;
  }
  void *uaddr = pagedir_get_page(cur->pagedir, usr_ptr);
  return (uaddr != NULL&&is_user_vaddr(usr_ptr));
}

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&open_files);
  lock_init(&fs_lock);
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
    uint32_t *esp = (uint32_t *)f->esp;
    if (!is_valid_ptr(esp))
    {
        // printf("valid");
        exit(-1);
    }
    int syscall_number = *esp;
    switch (syscall_number)

    {
    case SYS_HALT:
        halt();
        break;
    case SYS_EXIT:
        exit(*(esp + 1));
        break;
    case SYS_EXEC:
        // printf("execute!\n");
        f->eax = exec((char *)*(esp + 1));
        break;
    case SYS_WAIT:
        f->eax = wait(*(esp + 1));
        // printf("waiting...\n");
        break;
    case SYS_CREATE:
        f->eax = create((char *)*(esp + 1), *(esp + 2));
        break;
    case SYS_REMOVE:
        f->eax = remove((char *)*(esp + 1));
        break;
    case SYS_OPEN:
        f->eax = open((char *)*(esp + 1));
        break;
    case SYS_FILESIZE:
        f->eax = filesize(*(esp + 1));
        break;
    case SYS_READ:
        f->eax = read(*(esp + 1), (void *)*(esp + 2), *(esp + 3));
        break;
    case SYS_WRITE:
        f->eax = write(*(esp + 1), (void *)*(esp + 2), *(esp + 3));
        break;
    case SYS_SEEK:
        seek(*(esp + 1), *(esp + 2));
        break;
    case SYS_TELL:
        // f->eax = tell(*(esp + 1));
        break;
    case SYS_CLOSE:
        // close(*(esp + 1));
        break;
    default:
    // printf("%dno system call!\n", *esp);
    break;
  }
    }


  

  // thread_exit ();


// pid_t exec(const char *cmd_line)
// {
//   struct thread *cur = thread_current();
//   tid_t tid = NULL;
//   if (!is_valid_ptr(cmd_line))
//   {
//     exit(-1);
//   }
//   else
//   { 
//     cur->child_load_status = 0;
//     tid = process_execute(cmd_line);
//     lock_acquire(&cur->lock_child);
//     cond_wait(&cur->child_load_status, &cur->lock_child);
//     if (cur->child_load_status == -1)
//     {
//       tid = -1;
//     }
//     lock_release(&cur->lock_child);
//   }
//   return tid;
// }

pid_t exec(const char *cmd_line) {
    if (!is_valid_ptr(cmd_line)) {
        exit(-1);
    }

    struct thread *cur = thread_current();
    tid_t tid = process_execute(cmd_line);

    cur->child_load_status = 0;
    lock_acquire(&cur->lock_child);
    while (cur->child_load_status == 0) {
        cond_wait(&cur->cond_child, &cur->lock_child);
    }
    if (cur->child_load_status == -1) {
        tid = -1;
    }
    lock_release(&cur->lock_child);

    return tid;
}

int wait(pid_t pid)
{
  return process_wait(pid);
}

void exit(int status)
{
  struct thread *cur = thread_current();
  struct thread *parent = thread_get_by_id(&cur->parent_id);
printf("%s: exit(%d)\n", thread_name(), status);
  // parent thread가 존재할 경우, current thread를 찾기 위해 children list를 검색한다.
  if (parent != NULL)
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
        // printf("나갑니다!\n");
        break;
      }
    }
  }
  thread_exit();
}

void halt(void)
{
  shutdown_power_off();
}

int write(int fd, const void *buffer, unsigned size) // 내코드 아님
{
  struct file_descriptor *fd_struct;
  int status = 0;

  unsigned buffer_size = size;
  void *buffer_tmp = buffer;

  /* check the user memory pointing by buffer are valid */
  while (buffer_tmp != NULL)
  {
    if (!is_valid_ptr(buffer_tmp))
    {
      exit(-1);
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
  lock_acquire(&fs_lock);
  if (fd == 0)
  {

    status = -1;
  }
  else if (fd == 1)
  {
    putbuf(buffer, size);
    ;
    status = size;
  }
  else
  {
    // 지금 여기//
    fd_struct = get_open_file(fd);
    if (fd_struct != NULL)
    {
      status = file_write(fd_struct->file_struct, buffer, size);
    }
  }
  lock_release(&fs_lock);
  return status;
}

struct file_descriptor *
get_open_file(int fd)// 내 코드 아님
{

  struct list_elem *e;
  struct file_descriptor *fd_struct;
  e = list_tail(&open_files);
  while ((e = list_prev(e)) != list_head(&open_files))
  {
    fd_struct = list_entry(e, struct file_descriptor, elem);
    if (fd_struct->fd_num == fd)
      return fd_struct;
  }
  return NULL;
}

void close_file_by_owner (tid_t tid)// 내코드아님
{
  struct list_elem *e;
  struct list_elem *next;
  struct file_descriptor *fd_struct; 
  e = list_begin (&open_files);
  while (e != list_tail (&open_files)) 
    {
      next = list_next (e);
      fd_struct = list_entry (e, struct file_descriptor, elem);
      if (fd_struct->owner == tid)
	{
	  list_remove (e);
	  file_close (fd_struct->file_struct);
          free (fd_struct);
	}
      e = next;
    }
}

//내코드아님
int read(int fd, void* buffer, unsigned size){
 struct file_descriptor *fd_struct;
  int status = 0;
  struct thread *t = thread_current ();

  unsigned buffer_size = size;
  void * buffer_tmp = buffer;

  /* check the user memory pointing by buffer are valid */
  while (buffer_tmp != NULL)
    {
      if (!is_valid_ptr (buffer_tmp))
	exit (-1);
      
      /* Advance */
      if (buffer_size == 0)
	{
	  /* terminate the checking loop */
	  buffer_tmp = NULL;
	}
      else if (buffer_size > PGSIZE)
	{
	  buffer_tmp += PGSIZE;
	  buffer_size -= PGSIZE;
	}
      else
	{
	  /* last loop */
	  buffer_tmp = buffer + size - 1;
	  buffer_size = 0;
	}
    }

  lock_acquire (&fs_lock);   
  if (fd == 1)
      status = -1;
  else if (fd == 0)
    {
      uint8_t c;
      unsigned counter = size;
      uint8_t *buf = buffer;
      while (counter > 1 && (c = input_getc()) != 0)
        {
          *buf = c;
          buffer++;
          counter--; 
        }
      *buf = 0;
      status = size - counter;
    }
  else 
    {
      fd_struct = get_open_file (fd);
      if (fd_struct != NULL)
	status = file_read (fd_struct->file_struct, buffer, size);
    }
  lock_release (&fs_lock);
  return status;
}

bool create(const char *file_name, unsigned size)
{
    if (!is_valid_ptr(file_name))
        exit(-1);

    lock_acquire(&fs_lock);
    bool status = filesys_create(file_name, size);
    lock_release(&fs_lock);

    return status;
}

int open(const char *file_name)
{
    if (!is_valid_ptr(file_name))
        exit(-1);

    lock_acquire(&fs_lock);
    struct file *f = filesys_open(file_name);
    int status = -1;

    if (f != NULL)
    {
        struct file_descriptor *fd = calloc(1, sizeof *fd);
        fd->fd_num = allocate_fd();
        fd->owner = thread_current()->tid;
        fd->file_struct = f;
        list_push_back(&open_files, &fd->elem);
        status = fd->fd_num;
    }
    lock_release(&fs_lock);

    return status;
}


allocate_fd()
{
  static int fd_current = 1;
  return ++fd_current;
}


bool remove(const char *file_name)
{
    if (!is_valid_ptr(file_name))
        exit(-1);

    lock_acquire(&fs_lock);
    bool status = filesys_remove(file_name);
    lock_release(&fs_lock);

    return status;
}
int filesize(int fd)
{
    lock_acquire(&fs_lock);
    struct file_descriptor *fd_struct = get_open_file(fd);
    int status = fd_struct ? file_length(fd_struct->file_struct) : -1;
    lock_release(&fs_lock);

    return status;
}

// void close(int fd)
// {
//     lock_acquire(&fs_lock);
//     struct file_descriptor *fd_struct = get_open_file(fd);
//     if (fd_struct && fd_struct->owner == thread_current()->tid)
//         file_close(fd);
//     lock_release(&fs_lock);
//     return ;
// }
void seek(int fd, unsigned position)
{
    lock_acquire(&fs_lock);
    struct file_descriptor *fd_struct = get_open_file(fd);
    if (fd_struct)
        file_seek(fd_struct->file_struct, position);
    lock_release(&fs_lock);
}

// unsigned tell(int fd)
// {
//     lock_acquire(&fs_lock);
//     struct file_descriptor *fd_struct = get_open_file(fd);
//     unsigned status = fd_struct ? file_tell(fd_struct->file_struct) : -1;
//     lock_release(&fs_lock);

//     return status;
// }