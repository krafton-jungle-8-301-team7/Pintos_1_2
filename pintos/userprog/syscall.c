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
#include "threads/synch.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"
#include "threads/palloc.h"

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
		//if(exec(arg0) ==-1 )syscall_exit(-1) ;
		printf("🧐 syscall_handler: arg0 (cmd_line) = %p\n", (char *)arg0);
    	printf("🧐 pml4_get_page = %p\n", pml4_get_page(thread_current()->pml4, (void *)arg0));
		f->R.rax = exec((const char*)f->R.rdi);	// TID 저장
		if ((int)f->R.rax == -1) {
			syscall_exit(-1);
		}
		break;
	}
	// printf ("system call!\n");
	// thread_exit ();
}
void check_user_address(const void *uaddr) {//user memory access
    /* if (uaddr == NULL || !is_user_vaddr(uaddr) || pml4_get_page(thread_current()->pml4, uaddr) == NULL) // NULL 넘겼는지 || 유저영역인지 || 일부만 유효? 시작 끝이 페이지 테이블에 매핑 되어있는지 
        syscall_exit(-1); // 잘못된 주소면 프로세스 종료 */
	struct thread *cur = thread_current();

    if (uaddr == NULL) {
        printf("❌ check_user_address: uaddr == NULL\n");
        syscall_exit(-1);
    }

    if (!is_user_vaddr(uaddr)) {
        printf("❌ check_user_address: not a user vaddr: %p\n", uaddr);
        syscall_exit(-1);
    }

    void *mapped = pml4_get_page(cur->pml4, uaddr);
    if (mapped == NULL) {
        printf("❌ check_user_address: address not mapped in pml4: %p\n", uaddr);
        syscall_exit(-1);
    }

    printf("✅ check_user_address: passed for %p (mapped = %p)\n", uaddr, mapped);
}

int syscall_exit(int status){
	struct thread *cur = thread_current(); //프로세스의 커널 스레드.
	printf("⚠️ syscall_exit: tid=%d, name=%s, status=%d\n", cur->tid, cur->name, status);/* 🧐🧐🧐🧐🧐*/
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


int exec(const char *cmd_line)
{
	printf("🧨 syscall_exec 진입했다!!!!, cmd_line = %s\n", cmd_line);
	
	check_user_address(cmd_line); 

	char *cmd_line_copy = palloc_get_page(0);
	if (cmd_line_copy == NULL)
		return -1;						  
	strlcpy(cmd_line_copy, cmd_line, PGSIZE); 

	printf("exec: starting for %s\n", cmd_line);

	if (process_exec(cmd_line_copy) == -1)
		return -1;
}