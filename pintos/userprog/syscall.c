#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);


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
             check_user_address(arg0);
             f->R.rax = process_exec(arg0);
             break;
		case SYS_CREATE:
		     check_user_address((void *)arg0);    // 파일 이름 포인터 검증
		     f->R.rax = syscall_create((const char *)arg0, (unsigned)arg1);
		     break;
		case SYS_OPEN:
		     check_user_address((void *)arg0);
			 f->R.rax = syscall_open((const char *)arg0);
			 break;
		case SYS_CLOSE:
		     f->R.rax = syscall_close((int)arg0);
			 break;
	
	}
	// printf ("system call!\n");
	// thread_exit ();
}
void check_user_address(const void *uaddr) {//user memory access
    if (uaddr == NULL || !is_user_vaddr(uaddr) || pml4_get_page(thread_current()->pml4, uaddr) == NULL) // NULL 넘겼는지 || 유저영역인지 || 일부만 유효? 시작 끝이 페이지 테이블에 매핑 되어있는지 
        // thread_exit(); // 잘못된 주소면 커널 스레드 종료
		syscall_exit(-1); // 
}

int syscall_exit(int status){
	struct thread *cur = thread_current(); //프로세스의 커널 스레드.
    cur->exit_status = status; // 부모에게 전달할 종료 상태
         // 종료 처리
	// sema_up(cur->exit_sema);
    thread_exit(); 
}

int syscall_write(int fd,void * buffer, unsigned size){
	
	//fd1 -> stdout ->  FDT -> innode table->dev/tty에 출력
	if (fd == 1) {  // STDOUT
        putbuf(buffer, size);
        return size;
    }
	return -1;
}

int syscall_wait(tid_t pid){
 //sema로 자식프로세스 종료 기다림. wait sema 만들고
	return process_wait(pid);
 //자식이 exit시에 넘긴 status 읽음.
}

int syscall_create(const char *file, unsigned initial_size) {
	if (file == NULL) return false;     // NULL 포인터는 무시
	check_user_address((void *)file);   // 포인터 유효성 검사

	return filesys_create(file, initial_size);  // 파일 만들어 줘
}

int syscall_open(const char *file) {
	struct thread *cur = thread_current();

	// 포인터가 NULL이거나 잘못된 주소면 즉시 종료
	if (file == NULL || !is_user_vaddr(file) || pml4_get_page(cur->pml4, file) == NULL)
	    syscall_exit(-1);

	// 파일 열기
	struct file *f = filesys_open(file);
	if (f == NULL)
	    return -1;
    // 빈 fd 번호 찾기 (0,1은 stdin, stdout이므로 건너뛰기)
	for (int fd = 2; fd < FD_LIMIT; fd++) {
		if (cur->fd_table[fd] == NULL) {
			cur->fd_table[fd] = f;
			return fd;
		}
	}
	// 빈 fd 없음 -> 파일 닫고 실패
	file_close(f);
	return -1;
}

int syscall_close(int fd) {
	struct thread *cur = thread_current();

	// fd 범위가 유효한지 확인
	// (0,1은 stdin/stdout이고, 범위도 벗어나면 안 됨)
	if (fd < 2 || fd >= FD_LIMIT)
	    return -1;

	struct file *file_to_close = cur->fd_table[fd];

	// 이미 닫힌 파일이거나 잘못된 포인터면 실패
	if (file_to_close == NULL || !is_kernel_vaddr(file_to_close))
	    return -1;

	// 열려 있던 파일 닫기
	file_close(file_to_close);

	// fd_table에서 숙청
	cur->fd_table[fd] = NULL;

	return 0;  // 성공~!
}