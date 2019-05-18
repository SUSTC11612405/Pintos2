#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "lib/user/syscall.h"
#include "list.h"
#include "process.h"


static void syscall_handler (struct intr_frame *);
void* check_addr(const void *vaddr);
extern bool running;


struct file_descriptor{
  int fd;
  struct file * ptr;
  struct list_elem elem;
};

struct file_descriptor *list_search(struct list* files, int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

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
void close_file(struct list* files, int fd);

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int * esp=f->esp;

  check_addr(esp);

  int system_call = *esp;
  switch (system_call)
  {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      check_addr(esp+1);
      exit((int)*(esp+1));
      break;
    case SYS_EXEC:
      check_addr(esp+1);
      check_addr(*(esp+1));
      f->eax = (uint32_t)exec((const char *)*(esp+1));
      break;
    case SYS_WAIT:
      check_addr(esp+1);
      f->eax = wait((pid_t)*(esp+1));
      break;
    case SYS_CREATE:
      check_addr(esp+5);
      check_addr(*(esp+4));
      f->eax = create((const char*)*(esp+4),(unsigned)*(esp+5));
      break;
    case SYS_REMOVE:
      check_addr(esp+1);
      check_addr(*(esp+1));
      f->eax = remove((const char*)*(esp+1));
      break;
    case SYS_OPEN:
      check_addr(esp+1);
      check_addr(*(esp+1));
      f->eax = (uint32_t)open((const char *)*(esp+1));
      break;
    case SYS_FILESIZE:
      check_addr(esp+1);
      f->eax = filesize((int)*(esp+1));
      break;
    case SYS_READ:
      check_addr(esp+7);
      check_addr(*(esp+6));
      f->eax = (uint32_t)read((int)*(esp+5),(const void*)*(esp+6),(unsigned)*(esp+7));
      break;
    case SYS_WRITE:
      check_addr(esp+7);
      check_addr(*(esp+6));
      f->eax = (uint32_t)write((int)*(esp+5),(const void*)*(esp+6),(unsigned)*(esp+7));
      break;
    case SYS_SEEK:
      check_addr(esp+5);
      seek((int)*(esp+4),(unsigned)*(esp+5));
      break;
    case SYS_TELL:
      check_addr(esp+1);
      f->eax = tell((int)*(esp+1));
      break;
    case SYS_CLOSE:
      check_addr(esp+1);
      close((int)*(esp+1));
      break;
    default:;
  }
}

void halt(void){
  shutdown_power_off();
}

void exit(int status){
  struct list_elem *e;

  for (e = list_begin (&thread_current()->parent->child_proc); e != list_end (&thread_current()->parent->child_proc); e = list_next (e)){
    struct child *f = list_entry (e, struct child, elem);
    if(f->tid == thread_current()->tid){
      f->used = true;
      f->exit_error = status;
    }
  }
  thread_current()->exit_error = status;
  if(thread_current()->parent->waitingon == thread_current()->tid)
    sema_up(&thread_current()->parent->child_lock);

  thread_exit();
}

pid_t exec(const char *cmd_line){
  acquire_filesys_lock();
  //lock_acquire(&filesys_lock);
  char * file_name = malloc (strlen(cmd_line)+1);
  strlcpy(file_name, cmd_line, strlen(cmd_line)+1);
  char * save_ptr;
  file_name = strtok_r(file_name," ",&save_ptr);
  struct file* f = filesys_open (file_name);
  if(f==NULL){
    release_filesys_lock();
    //lock_release(&filesys_lock);
    return -1;
  }else{
    file_close(f);
    release_filesys_lock();
    //lock_release(&filesys_lock);
    return process_execute(cmd_line);
  }
}

int wait(pid_t pid){
  //if(pid==-1) return -1;
  return process_wait(pid);
}

bool create(const char *file, unsigned initial_size){
  bool success;
  acquire_filesys_lock();
  //lock_acquire(&filesys_lock);
  success = filesys_create(file,initial_size);
  release_filesys_lock();
  //lock_release(&filesys_lock);
  return success;
}

bool remove(const char *file){
  bool success;
  acquire_filesys_lock();
  //lock_acquire(&filesys_lock);
  if(filesys_remove(file)==NULL)
    success = false;
  else
    success = true;
  release_filesys_lock();
  //lock_release(&filesys_lock);
  return success;
}

int open(const char *file){
  int fd = -1;
  acquire_filesys_lock();
  //lock_acquire(&filesys_lock);
  struct file * f_ptr = filesys_open(file);
  release_filesys_lock();
  //lock_release(&filesys_lock);
  if(f_ptr==NULL)
    fd = -1;
  else{
    struct file_descriptor * new_file = malloc(sizeof(struct file_descriptor));
    new_file->ptr = f_ptr;
    new_file->fd = thread_current()->fd_count;
    thread_current()->fd_count++;
    list_push_back (&thread_current()->files, &new_file->elem);
    fd = new_file->fd;
  }
  return fd;
}

int filesize(int fd){
  int size = -1;
  struct file_descriptor * file_desc;
  acquire_filesys_lock();
  //lock_acquire(&filesys_lock);
  file_desc = list_search(&thread_current()->files, fd);
  if (file_desc != NULL){
    size = file_length(file_desc->ptr);
  }
  release_filesys_lock();
  //lock_release(&filesys_lock);
  return size;
}

int read(int fd, void *buffer, unsigned size){
  struct file_descriptor *file_desc;
  int bytes_written = 0;
  if(fd == STDIN_FILENO) {
    int i;
    uint8_t* buffer = *buffer;
    for(i=0;i<size;i++)
      buffer[i] = input_getc();
    bytes_written = size;
  }else{
    file_desc = list_search(&thread_current()->files, fd);
    if(file_desc==NULL){
      return -1;
    }else{
      acquire_filesys_lock();
      //lock_acquire(&filesys_lock);
      bytes_written = file_read(file_desc->ptr,buffer,size);
      release_filesys_lock();
      //lock_release(&filesys_lock);
    }
  }
  return bytes_written;
}

int write(int fd, const void *buffer, unsigned size){
  struct file_descriptor *file_desc;
  int bytes_written = 0;
  if(fd==STDOUT_FILENO) {
    putbuf (buffer, size);
    return size;
  } else {
    file_desc = list_search(&thread_current()->files, fd);
    if(file_desc==NULL){
      return -1;
    }else{
      acquire_filesys_lock();
      //lock_acquire(&filesys_lock);
      bytes_written = file_write(file_desc->ptr,buffer,size);
      release_filesys_lock();
      //lock_release(&filesys_lock);
    }
  }
  return bytes_written;
}

void seek(int fd, unsigned position){
  struct file_descriptor *file_desc;
  acquire_filesys_lock();
  //lock_acquire(&filesys_lock);
  file_desc = list_search(&thread_current()->files, fd);
  if(file_desc != NULL)
    file_seek(file_desc->ptr, position);
  release_filesys_lock();
  //lock_release(&filesys_lock);
  return;
}
unsigned tell(int fd){
  struct file_descriptor *file_desc;
  int bytes = 0;
  acquire_filesys_lock();
  //lock_acquire(&filesys_lock);
  file_desc = list_search(&thread_current()->files, fd);
  if(file_desc != NULL)
    bytes = file_tell(file_desc->ptr);
  release_filesys_lock();
  //lock_release(&filesys_lock);
  return bytes;
}
void close(int fd){
  acquire_filesys_lock();
  //lock_acquire(&filesys_lock);
  close_file(&thread_current()->files, fd);
  release_filesys_lock();
  //lock_release(&filesys_lock);
}

void* check_addr(const void *vaddr){
  if (!is_user_vaddr(vaddr)){
    exit(-1);
    return 0;
  }
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr){
    exit(-1);
    return 0;
  }
  return ptr;
}

void close_file(struct list* files, int fd){
  struct list_elem * e;
  struct file_descriptor * f;
  for (e = list_begin (files); e != list_end (files); e = list_next (e)){
    f = list_entry (e, struct file_descriptor, elem);
    if(f->fd == fd){
      file_close(f->ptr);
      list_remove(e);
    }
  }
  free(f);
}

void close_all_files(struct list* files){
  struct list_elem * e;
  while(!list_empty(files)){
    e = list_pop_front(files);
    struct file_descriptor * f = list_entry (e, struct file_descriptor, elem);
    file_close(f->ptr);
    list_remove(e);
    free(f);
  }   
}

struct file_descriptor* list_search(struct list* files, int fd){
  struct list_elem *e;
  for (e = list_begin (files); e != list_end (files); e = list_next (e)){
    struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
    if(f->fd == fd)
      return f;
  }
  return NULL;
}

