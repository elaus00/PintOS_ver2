#include "userprog/syscall.h"
#include "devices/input.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"


static pid_t exec(const char *);
static void halt(void);
static void exit(int);
static int write(int, const void *, unsigned);
void close_file_by_owner(tid_t tid);

static void syscall_handler(struct intr_frame *);

void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
void close_open_file(int fd);

// 여기까지 sys_hanlder에 들어가는 함수들

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
    return uaddr != NULL;
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
        f->eax = exec((char *)*(esp + 1));
        break;
    case SYS_WAIT:
        f->eax = wait(*(esp + 1));
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
        f->eax = tell(*(esp + 1));
        break;
    case SYS_CLOSE:
        close(*(esp + 1));
        break;
    }
}

void halt(void)
{
    shutdown_power_off();
}

void exit(int status)
{
    struct thread *cur = thread_current();
    struct thread *parent = thread_get_by_id(cur->parent_id);
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

int wait(pid_t pid)
{
    return process_wait(pid);
}

pid_t exec(const char *cmd_line)
{

    struct thread *cur = thread_current();
    tid_t tid = process_execute(cmd_line);

    if (!is_valid_ptr(cmd_line))
    {
        exit(-1);
    }
    else
    {
        cur->child_load_status = 0;
        lock_acquire(&cur->lock_child);
        cond_wait(&cur->child_load_status, &cur->lock_child);
        if (cur->child_load_status == -1)
        {
            tid = -1;
        }
        lock_release(&cur->lock_child);
    }
    return tid;
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

bool remove(const char *file_name)
{
    if (!is_valid_ptr(file_name))
        exit(-1);

    lock_acquire(&fs_lock);
    bool status = filesys_remove(file_name);
    lock_release(&fs_lock);

    return status;
}

int open(const char *file_name)
{
    if (!is_valid_ptr(file_name))
        exit(-1);

    lock_acquire(&fs_lock);
    struct file *f = filesys_open(&file_name);
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

int filesize(int fd)
{
    lock_acquire(&fs_lock);
    struct file_descriptor *fd_struct = get_open_file(fd);
    int status = fd_struct ? file_length(fd_struct->file_struct) : -1;
    lock_release(&fs_lock);

    return status;
}

int read(int fd, void* buffer, unsigned size) {
    struct file_descriptor *fd_struct;
    int status = 0;
    struct thread *t = thread_current();
    
    // Check if the user memory pointed by buffer is valid
    unsigned buffer_size = size;
    void *buffer_tmp = buffer;
    while (buffer_size > 0) {
        if (!is_valid_ptr(buffer_tmp))
            exit(-1);
        // Advance to the next page
        buffer_tmp += PGSIZE;
        buffer_size = (buffer_size > PGSIZE) ? buffer_size - PGSIZE : 0;
    }

    lock_acquire(&fs_lock);
    if (fd == STDOUT_FILENO) {
        status = -1;  // Writing to stdout is not supported
    } else if (fd == STDIN_FILENO) {
        // Read from standard input
        unsigned counter = size;
        uint8_t *buf = buffer;
        while (counter > 0) {
            *buf = input_getc();
            buf++;
            counter--;
        }
        status = size;
    } else {
        fd_struct = get_open_file(fd);
        if (fd_struct != NULL) {
            status = file_read(fd_struct->file_struct, buffer, size);
        } else {
            status = -1;
        }
    }
    lock_release(&fs_lock);
    return status;
}

int write(int fd, const void *buffer, unsigned size) {
    struct file_descriptor *fd_struct;
    int status = 0;

    // Check if the user memory pointed by buffer is valid
    unsigned buffer_size = size;
    const void *buffer_tmp = buffer;
    while (buffer_size > 0) {
        if (!is_valid_ptr(buffer_tmp))
            exit(-1);
        buffer_tmp += PGSIZE;
        buffer_size = (buffer_size > PGSIZE) ? buffer_size - PGSIZE : 0;
    }

    lock_acquire(&fs_lock);
    if (fd == STDIN_FILENO) {
        status = -1;  // Reading from stdin is not supported
    } else if (fd == STDOUT_FILENO) {
        // Write to standard output
        putbuf(buffer, size);
        status = size;
    } else {
        // Write to a file
        fd_struct = get_open_file(fd);
        if (fd_struct != NULL) {
            status = file_write(fd_struct->file_struct, buffer, size);
        } else {
            status = -1;
        }
    }
    lock_release(&fs_lock);
    return status;
}


void seek(int fd, unsigned position)
{
    lock_acquire(&fs_lock);
    struct file_descriptor *fd_struct = get_open_file(fd);
    if (fd_struct)
        file_seek(fd_struct->file_struct, position);
    lock_release(&fs_lock);
}

unsigned tell(int fd)
{
    lock_acquire(&fs_lock);
    struct file_descriptor *fd_struct = get_open_file(fd);
    unsigned status = fd_struct ? file_tell(fd_struct->file_struct) : -1;
    lock_release(&fs_lock);

    return status;
}

void close(int fd)
{
    lock_acquire(&fs_lock);
    struct file_descriptor *fd_struct = get_open_file(fd);
    if (fd_struct && fd_struct->owner == thread_current()->tid)
        file_close(fd);
    lock_release(&fs_lock);
}

static int read_from_stdin(void *buffer, unsigned size) {
    uint8_t *buf = buffer;
    unsigned i;
    for (i = 0; i < size; i++)
        buf[i] = input_getc();
    return size;
}

struct file_descriptor *
get_open_file(int fd)
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

void close_file_by_owner(tid_t tid)
{
    struct list_elem *e;
    struct list_elem *next;
    struct file_descriptor *fd_struct;
    e = list_begin(&open_files);
    while (e != list_tail(&open_files))
    {
        next = list_next(e);
        fd_struct = list_entry(e, struct file_descriptor, elem);
        if (fd_struct->owner == tid)
        {
            list_remove(e);
            file_close(fd_struct->file_struct);
            free(fd_struct);
        }
        e = next;
    }
}

int
allocate_fd ()
{
  static int fd_current = 1;
  return ++fd_current;
}
