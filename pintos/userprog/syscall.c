#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"
#include "threads/palloc.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
static bool put_user (uint8_t *udst, uint8_t byte);
static int64_t get_user (const uint8_t *uaddr);

void validate_buffer(const void *buffer, size_t size);
struct file_descriptor *find_file_descriptor(int fd);
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int syscall_num = f->R.rax; //인자 다 받아오고.
	uint64_t arg0 = f->R.rdi;
	uint64_t arg1 = f->R.rsi;
	uint64_t arg2 = f->R.rdx;
	uint64_t arg3 =	f->R.r10;
	uint64_t arg4 = f->R.r8;
	uint64_t arg5 = f->R.r9;
	switch (syscall_num) {
		case SYS_EXIT:
			syscall_exit((int) arg0);
			break;
		case SYS_WRITE:
			f->R.rax = syscall_write((int) arg0,(void *) arg1, (unsigned) arg2);
			break;
		case SYS_HALT:
			power_off();
			break;
		case SYS_FORK:
			f->R.rax = process_fork((const char *)arg0,f);
			break;
		case SYS_WAIT:
			f->R.rax = syscall_wait((tid_t) arg0);
			break;
		case SYS_EXEC:
			if(exec(arg0) ==-1 )syscall_exit(-1) ;
			break;
		case SYS_CREATE:
			f->R.rax = syscall_create((const char *)arg0, (unsigned)arg1);
			break;
		case SYS_OPEN:
			f->R.rax = syscall_open((const char *)arg0);
			break;
		case SYS_CLOSE:
			f->R.rax = syscall_close((int)arg0);
			break;
		case SYS_READ:
			f->R.rax = syscall_read((int)arg0, (void *)arg1, (unsigned)arg2);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(arg0);
			break;
		default:
			break;
	}
	// printf ("system call!\n");
	// thread_exit ();
}
void check_user_address(const void *uaddr) {//user memory access
    if (uaddr == NULL || !is_user_vaddr(uaddr) || pml4_get_page(thread_current()->pml4, uaddr) == NULL) // NULL 넘겼는지 || 유저영역인지 || 일부만 유효? 시작 끝이 페이지 테이블에 매핑 되어있는지 
        syscall_exit(-1); // 잘못된 주소면 프로세스 종료
}

int syscall_exit(int status){
	struct thread *cur = thread_current(); //프로세스의 커널 스레드.
    cur->exit_status = status; // 부모에게 전달할 종료 상태
         // 종료 처리
	// sema_up(cur->exit_sema);
    thread_exit(); 
}

int syscall_write(int fd,void * buffer, unsigned size){
	check_user_address(buffer);
	if (size == 0) return 0;
	struct thread *cur = thread_current();
	validate_buffer(buffer, size);

	struct file *target_file = cur->fd_table[fd];
	
	if (fd >= 2 && target_file != NULL && cur->running_file != NULL &&
	file_get_inode(target_file) == file_get_inode(cur->running_file)) {
	return 0;
}

	//fd1 -> stdout ->  FDT -> innode table->dev/tty에 출력
	if (fd == 1) {  // STDOUT
		void *kbuf = palloc_get_page(0);
		if (kbuf == NULL)
			syscall_exit(-1);
		memcpy(kbuf, buffer, size);
		putbuf(kbuf, size);
		palloc_free_page(kbuf);
		return size;
    }
	// 파일 출력
	if (fd >= 2 && fd < FD_LIMIT) {
		void *kbuf = palloc_get_page(0);
		if (kbuf == NULL)
			syscall_exit(-1);
		memcpy(kbuf, buffer, size);
		struct file *file = cur->fd_table[fd];   // 해당 fd에 열려있는 파일 가져오기
		if (file == NULL) {
			palloc_free_page(kbuf);
			return -1;             // 안 열려이씀? 실패 ㅋ
		}
		lock_acquire(&filesys_lock);             // 파일 시스템 접근 락 겟또
		int bytes_written = file_write(file, kbuf, size);  // 파일에 쓰기
		lock_release(&filesys_lock);             // 해제한 락도 락이다.
		palloc_free_page(kbuf);

		return bytes_written;                    // 실제로 쓴 바이트 수 반환
	}
	return -1;
}

int syscall_wait(tid_t pid){
 //sema로 자식프로세스 종료 기다림. wait sema 만들고
	return process_wait(pid);
 //자식이 exit시에 넘긴 status 읽음.
}


int exec(const char *cmd_line)
{
	check_user_address(cmd_line); 

	char *cmd_line_copy;
	cmd_line_copy = palloc_get_page(0);
	if (cmd_line_copy == NULL)
		return -1;						  
	strlcpy(cmd_line_copy, cmd_line, PGSIZE); 
	// printf("EXEC: cmd_line_copy contains: %s\n", cmd_line_copy);
	// 스레드의 이름을 변경하지 않고 바로 실행한다.
	if (process_exec(cmd_line_copy) == -1)
		return -1; // 실패 시 status -1로 종료한다.
	// check_user_address(cmd_line);

    // off_t size = strlen(cmd_line) + 1;
    // char *cmd_copy = palloc_get_page(PAL_ZERO);

    // if (cmd_copy == NULL)
    //     return -1;

    // memcpy(cmd_copy, cmd_line, size);

    // return process_exec(cmd_copy);
}

int syscall_create(const char *file, unsigned initial_size) {
	check_user_address(file);   // 포인터 유효성 검사

	return filesys_create(file, initial_size);  // 파일 만들어 줘
}

int syscall_open(const char *file) {
	lock_acquire(&filesys_lock);
	struct thread *cur = thread_current();

	// 포인터가 NULL이거나 잘못된 주소면 즉시 종료

	check_user_address(file);


	// 파일 열기
	
	struct file *f = filesys_open(file);
	if (f == NULL){
		return -1;
	}
    // 빈 fd 번호 찾기 (0,1은 stdin, stdout이므로 건너뛰기)
	for (int fd = 2; fd < FD_LIMIT; fd++) {
		if (cur->fd_table[fd]== NULL) {
			cur->fd_table[fd] = f;

			
			// cur->fd_table[file_descriptor->fd] = file_descriptor;
			lock_release(&filesys_lock);
			return fd;
		}
	}

	lock_release(&filesys_lock);
	// 빈 fd 없음 -> 파일 닫고 실패
	file_close(f);
	return -1;
}

int syscall_close(int fd) {
	struct thread *cur = thread_current();
	if (1 >= fd) return;
	struct file *file_to_close = cur->fd_table[fd];
	if (file_to_close == NULL)
		return;
	file_close(file_to_close);
	cur->fd_table[fd] = NULL;
	return 0;  // 성공~!
}

int syscall_read(int fd , void *buffer, unsigned size) {
    if (size == 0)
        return 0;

    if (buffer == NULL||fd<0)
        syscall_exit(-1);

    validate_buffer(buffer, size);
    struct thread *cur = thread_current();

    if (fd == 0) {
        for (unsigned i = 0; i < size; i++) {
            ((char *)buffer)[i] = input_getc();
        }
        return size;
    }
	else if (fd == 1)
		return -1;

    else {
		if (size == 0)
		    return 0;


        struct file *file = cur->fd_table[fd];
        if (file == NULL)
            return -1;

        void *kbuf = palloc_get_page(0);
        if (kbuf == NULL)
            syscall_exit(-1);

        lock_acquire(&filesys_lock);
        int bytes_read = file_read(file, kbuf, size);
        

        for (int i = 0; i < bytes_read; i++) {
            if (!put_user((uint8_t *)buffer + i, ((uint8_t *)kbuf)[i])){
				palloc_free_page(kbuf);
				lock_release(&filesys_lock);
                syscall_exit(-1);
			}

        }

        palloc_free_page(kbuf);
		lock_release(&filesys_lock);
        return bytes_read;
    }

    return -1;
}

void validate_buffer(const void *buffer, size_t size) {
	if (size == 0)
	    return;
		
    if (buffer == NULL && size > 0)
	    syscall_exit(-1);

    uint8_t *start = (uint8_t *)buffer;
    uint8_t *end = (uint8_t *)buffer + size - 1;

    for (uint8_t *addr = pg_round_down(start); addr <= pg_round_down(end); addr += PGSIZE) {
        if (!is_user_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr) == NULL) {
            syscall_exit(-1);
        }
    }
}
struct file_descriptor *find_file_descriptor(int fd) {
	struct file_descriptor **fd_list = thread_current()->fd_table;
	ASSERT(fd_list != NULL);
	ASSERT(fd > 1);
	return fd_list[fd];
}

int filesize (int fd) {
	struct thread *cur = thread_current();
	return file_length(cur->fd_table[fd]);
}

/* Reads a byte at user virtual address UADDR.
 * UADDR must be below KERN_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int64_t
get_user (const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile (
    "movabsq $done_get, %0\n"
    "movzbq %1, %0\n"
    "done_get:\n"
    : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte) {
    int64_t error_code;
    __asm __volatile (
    "movabsq $done_put, %0\n"
    "movb %b2, %1\n"
    "done_put:\n"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}