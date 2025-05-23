/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"


bool cond_sema_priority_cmp(const struct list_elem *a,
                            const struct list_elem *b,
                            void *aux UNUSED);
extern bool list_DECS_priority(const struct list_elem *a,
                             const struct list_elem *b,
                             void *aux);

static void donate_priority(struct thread *t);
bool cond_sema_priority_cmp(const struct list_elem *a,
                            const struct list_elem *b,
                            void *aux UNUSED);\
bool thread_compare_donate_priority(const struct list_elem *higher, const struct list_elem *lower, void *aux UNUSED);


bool thread_compare_donate_priority(const struct list_elem *higher, const struct list_elem *lower, void *aux UNUSED) {
	return list_entry(higher, struct thread, d_elem)->priority > list_entry(lower, struct thread, d_elem)->priority;
}

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) {
	ASSERT (sema != NULL);

	sema->value = value;
	list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void
sema_down (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);
	ASSERT (!intr_context ());

	old_level = intr_disable ();
	while (sema->value == 0) {
		list_insert_ordered (&sema->waiters, &thread_current ()->elem,list_DECS_priority,NULL);
		thread_block ();
	}
	sema->value--;
	intr_set_level (old_level);;
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) {
	enum intr_level old_level;
	bool success;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level (old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) {
	enum intr_level old_level;

   struct thread *wakeupthread = NULL;
	ASSERT (sema != NULL);

	old_level = intr_disable ();
   
	if (!list_empty (&sema->waiters)){
      list_sort(&sema->waiters, list_DECS_priority, NULL);//소팅 한번 더
      wakeupthread = list_entry (list_pop_front (&sema->waiters),struct thread, elem);
		thread_unblock (wakeupthread);
   }

	sema->value++;
   
   intr_set_level (old_level);
   preemption_priority();

}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
	struct semaphore sema[2];
	int i;

	printf ("Testing semaphores...");
	sema_init (&sema[0], 0);
	sema_init (&sema[1], 0);
	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up (&sema[0]);
		sema_down (&sema[1]);
	}
	printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down (&sema[0]);
		sema_up (&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock) {
	ASSERT (lock != NULL);

	lock->holder = NULL;
	sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));

   struct thread *curr = thread_current();
   if(lock->holder !=NULL){//락 홀더가 안비어있으면
      curr->wait_on_lock = lock;//락을 쓸수 없으면 락의 주소를 저장.
      //형재 우선순위 저장? 이미 되어있는데 해야되나?, 리스트에서 도네이트된 스레드 조정.
      donate_priority(curr);//도네하고
   }
   sema_down (&lock->semaphore);//바로 세마 0으로 만듦(다른 쓰레드들 접근 못함)
   curr->wait_on_lock = NULL; //얻으면  NULL로 바꿔주기.
	lock->holder = curr;
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock) {
	bool success;

	ASSERT (lock != NULL);
	ASSERT (!lock_held_by_current_thread (lock));

	success = sema_try_down (&lock->semaphore);
	if (success)
		lock->holder = thread_current ();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (lock_held_by_current_thread (lock));

//When the lock is released, remove the thread that holds the lock 
//on donation list and set priority properly.
   struct thread *t;
   t = lock->holder;
	lock->holder = NULL;
   enum intr_level old_level = intr_disable();
   //donation 리스트 순회하면서 지금 wait_on_lock이 해제하는 lock인 애들을 remove list(d_elem)
   struct list_elem *cur_d_elem = list_begin (&t->donations);//리스트 시작지점
   struct list_elem *next_d_elem;
   while(cur_d_elem != list_end(&t->donations)){//도네이션 리스트 순회
      struct thread *cur_t = list_entry(cur_d_elem,struct thread, d_elem);
      next_d_elem = list_next(cur_d_elem);
      if(cur_t->wait_on_lock == lock){
         list_remove(cur_d_elem);
         cur_t->wait_on_lock = NULL;
      }
      
      cur_d_elem = next_d_elem;
   }
   refresh_priority(t);
	sema_up (&lock->semaphore);//세마 업 시에 선점을 하는데 sema업이 빠르면 바뀌지 않은 상태로 선점을 진행함 (언블럭 이후 선점함)
   intr_set_level (old_level);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
	ASSERT (lock != NULL);

	return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem {
	struct list_elem elem;              /* List element. */
	struct semaphore semaphore;         /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
	ASSERT (cond != NULL);

	list_init (&cond->waiters);
}
//세마포어 원소로 엔트리 찾아서 비교.
bool cond_sema_priority_cmp(const struct list_elem *a,
                            const struct list_elem *b,
                            void *aux UNUSED) {
	struct semaphore_elem *higher_sema = list_entry(a, struct semaphore_elem, elem);
	struct semaphore_elem *lower_sema = list_entry(b, struct semaphore_elem, elem);

	struct list *waiter_higher_sema = &(higher_sema->semaphore.waiters);
	struct list *watier_lower_sema = &(lower_sema->semaphore.waiters);

	return list_entry(list_begin(waiter_higher_sema), struct thread, elem)->priority >list_entry(list_begin(watier_lower_sema), struct thread, elem)->priority ;
}
/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) {
	struct semaphore_elem waiter;

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	sema_init (&waiter.semaphore, 0);
   // enum intr_level old_level = intr_disable();
	list_insert_ordered (&cond->waiters, &waiter.elem,cond_sema_priority_cmp,NULL);
   // intr_set_level (old_level);
	lock_release (lock); // 락을 갖고있는건 비효율적, 어차피 wait을 하면서 블락될것이므로 락(리소스)을 풀어두는게 나음.
	sema_down (&waiter.semaphore);
	lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	if (!list_empty (&cond->waiters)){ 
         list_sort(&cond->waiters, cond_sema_priority_cmp, NULL); 
         sema_up (&list_entry (list_pop_front (&cond->waiters),
					struct semaphore_elem, elem)->semaphore);
   }
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters))
		cond_signal (cond, lock);
}

//donation
static void donate_priority(struct thread *t){// 사용 전후에 인터럽트 껏다 켜줘야 될듯?
   int depth = 0;
   enum intr_level old_level = intr_disable();
   struct thread *curr = t;
   struct lock *lock=curr->wait_on_lock;
   //도네이션 체인-> depth = 8
   //현재 기부 스레드가 락의 홀더 보고 기부.->다음 홀더를 현재 스레드 변수로 변경->
   list_insert_ordered(&lock->holder->donations, &curr->d_elem, thread_compare_donate_priority, NULL);
   while(depth<8){

      lock=curr->wait_on_lock;
      if(lock ==NULL)break;
      struct thread *holder = lock->holder;

      // 우선순위 기부 -> 현재 기부하는 스레드만 기부.
      if (holder->priority < curr->priority)
         holder->priority = curr->priority;

      curr = holder;
      depth++;
   }
   intr_set_level (old_level);
}

