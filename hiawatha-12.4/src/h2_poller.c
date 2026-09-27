/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License. For a copy,
 * see http://www.gnu.org/licenses/gpl-2.0.html.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "config.h"

#ifdef ENABLE_HTTP2

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#if defined(HAVE_EPOLL)
#include <sys/epoll.h>
#elif defined(HAVE_KQUEUE)
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#else
#include <poll.h>
#endif
#include "h2_poller.h"

/* ==========================================================================
 *  The backends' own types, all three in one place: typedefs live at the top
 *  of the file. Only one branch compiles, selected by the same test that
 *  picks the backend sections below.
 * ======================================================================== */

#if defined(HAVE_EPOLL)

typedef struct {
	void  *data;
	short  events;       /* HP_* mask currently registered */
	char   registered;   /* 0 = this fd is not in the set */
} t_h2_poller_reg;

struct type_h2_poller {
	int                 epfd;
	int                 count;

	t_h2_poller_reg    *reg;
	int                 reg_size;

	struct epoll_event *events;     /* scratch for epoll_wait */
	int                 events_capacity;
};

#elif defined(HAVE_KQUEUE)

typedef struct {
	void  *data;
	short  events;       /* HP_* mask currently registered */
	int    out_index;    /* where this fd landed in the current batch, or -1 */
	char   registered;   /* 0 = this fd is not in the set */
} t_h2_poller_reg;

struct type_h2_poller {
	int               kq;
	int               count;

	t_h2_poller_reg  *reg;
	int               reg_size;

	struct kevent    *events;     /* scratch for kevent() output */
	int               events_capacity;
};

#else

struct type_h2_poller {
	struct pollfd  *fds;
	void          **data;
	int             count;
	int             capacity;

	/* fd -> index into fds[]/data[], stored as index + 1 so that a zeroed
	 * entry means "not registered".  That convention is what lets the shared
	 * h2_poller_grow_table() zero-fill the growth for both backends. */
	int            *slot;
	int             slot_size;
};

#endif

/* Which backend this build got, for the one report that should never have to
 * guess. Kept next to the includes so it cannot drift from them. */
const char *h2_poller_backend(void) {
#if defined(HAVE_EPOLL)
	return "epoll";
#elif defined(HAVE_KQUEUE)
	return "kqueue";
#else
	return "poll";
#endif
}

/* Grow an fd-indexed table to cover this descriptor number. Shared by all
 * three backends: each keeps a per-fd record so that add/mod/del are O(1) and
 * so that mod can tell "unchanged" from "changed" without asking the kernel.
 * Descriptor numbers are bounded by RLIMIT_NOFILE, which Hiawatha sets for
 * itself at startup -- but only with SetResourceLimits = yes (the default),
 * and a setrlimit that fails prints a line and carries on (hiawatha.c). Turn
 * the directive off and the bound is whatever the process inherited, which on
 * a desktop can be a million: the table then follows the highest descriptor
 * number ever handed out, at one record per number. Nothing here breaks, it
 * is simply not the ceiling this sentence used to name.
 * Returns the new size, or 0 on failure.
 */
static int h2_poller_grow_table(void **table, int size, size_t entry, int fd) {
	void *grown;
	int new_size;

	if (fd < size) {
		return size;
	}

	new_size = (size == 0) ? 64 : size;
	while (new_size <= fd) {
		if (new_size > INT_MAX / 2) {
			return 0;
		}
		new_size *= 2;
	}

	if ((grown = realloc(*table, (size_t)new_size * entry)) == NULL) {
		return 0;
	}

	/* Zero-fill is the "unregistered" state everywhere: the poll backend
	 * stores slot+1, epoll and kqueue a `registered` flag, so a zeroed entry
	 * means "not here" in all three.  The kqueue backend carries one field
	 * where 0 is a legal VALUE (out_index, a batch position), and it
	 * initialises that range itself right after this call. */
	memset((char*)grown + (size_t)size * entry, 0, (size_t)(new_size - size) * entry);

	*table = grown;

	return new_size;
}

/* FD_CLOEXEC after the fact, for the one creating call without an atomic
 * flag: kqueue() where kqueue1() is missing -- today that is macOS (see
 * h2_poller_create in the kqueue section). Split into a helper so the
 * failure path has a test that can actually reach it (tests/h2_cloexec):
 * fcntl on a freshly created descriptor does not fail on any supported
 * platform, a closed one fails reliably with EBADF.
 * Returns 0, or -1 with errno set. */
#if (defined(HAVE_KQUEUE) && !defined(HAVE_KQUEUE1)) || defined(H2_POLLER_TEST)

#ifdef H2_POLLER_TEST
/* Test seam, never part of a release build: forces the helper to fail so
 * that h2_poller_create()'s error path can be driven from the suite. */
static int h2_test_cloexec_fail = 0;
#endif

static int h2_fd_set_cloexec(int fd) {
	int flags;

#ifdef H2_POLLER_TEST
	if (h2_test_cloexec_fail) {
		errno = EBADF;
		return -1;
	}
#endif

	if ((flags = fcntl(fd, F_GETFD, 0)) == -1) {
		return -1;
	}
	if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
		return -1;
	}

	return 0;
}

#endif

#if defined(HAVE_EPOLL)

/* ========================================================================
 *  epoll(7) backend -- Linux
 *
 *  The point of this backend, and the reason the whole abstraction exists:
 *  a descriptor is registered ONCE and the kernel keeps the interest. There
 *  is no per-cycle array to build and none to copy in and out of the kernel,
 *  and the wait is O(ready) instead of O(registered).
 *
 *  LEVEL-TRIGGERED, deliberately: no EPOLLET. nginx uses edge-triggering and
 *  pays for it with a "read until EAGAIN or hang" contract in every handler.
 *  Hiawatha's handlers are not written that way -- h2_read_and_process()
 *  stops at a partial TLS record and comes back next round, which is exactly
 *  the case edge-triggering would lose.
 *
 *  NO EPOLLRDHUP either, and that is not an oversight: poll(2) has no such
 *  bit, so asking for it would make this backend report a state the poll
 *  backend cannot, and the two would stop being interchangeable. A peer that
 *  closed its write side shows up as EPOLLIN with a zero-byte read, which is
 *  what the poll backend delivers too.
 *
 *  reg[fd] is what makes h2_poller_mod() free when nothing changed: without
 *  it every refresh would be an epoll_ctl syscall, and the whole point of
 *  "call it whenever in doubt" would be gone.
 * ======================================================================== */

static uint32_t h2_poller_to_epoll_events(short events) {
	uint32_t result = 0;

	if (events & HP_IN) {
		result |= EPOLLIN;
	}
	if (events & HP_OUT) {
		result |= EPOLLOUT;
	}

	/* HP_HUP and HP_ERR are results, never interests: EPOLLHUP and EPOLLERR
	 * are reported whether or not they were asked for, exactly as their poll
	 * counterparts are. */

	return result;
}

static short h2_poller_from_epoll_events(uint32_t events) {
	short result = 0;

	if (events & EPOLLIN) {
		result |= HP_IN;
	}
	if (events & EPOLLOUT) {
		result |= HP_OUT;
	}
	if (events & EPOLLHUP) {
		result |= HP_HUP;
	}
	if (events & EPOLLERR) {
		result |= HP_ERR;
	}

	return result;
}

t_h2_poller *h2_poller_create(void) {
	t_h2_poller *poller;

	if ((poller = (t_h2_poller*)calloc(1, sizeof(t_h2_poller))) == NULL) {
		return NULL;
	}

	/* EPOLL_CLOEXEC in the creating call, not an fcntl() afterwards: Hiawatha
	 * forks CGI children from other threads, and between the two calls a fork
	 * inherits the descriptor that drives the event loop of every HTTP/2
	 * connection. */
	if ((poller->epfd = epoll_create1(EPOLL_CLOEXEC)) == -1) {
		free(poller);
		return NULL;
	}

	return poller;
}

int h2_poller_add(t_h2_poller *poller, int fd, short events, void *data) {
	struct epoll_event ev;
	int size;

	if ((poller == NULL) || (fd < 0)) {
		return -1;
	}

	if ((size = h2_poller_grow_table((void**)&poller->reg, poller->reg_size,
	     sizeof(t_h2_poller_reg), fd)) == 0) {
		return -1;
	}
	poller->reg_size = size;

	if (poller->reg[fd].registered) {
		/* Already registered. A caller error, and one worth failing on: it
		 * means two connections believe they own this descriptor. */
		return -1;
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = h2_poller_to_epoll_events(events);
	ev.data.ptr = data;

	if (epoll_ctl(poller->epfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		return -1;
	}

	poller->reg[fd].data = data;
	poller->reg[fd].events = events;
	poller->reg[fd].registered = 1;
	poller->count++;

	return 0;
}

int h2_poller_mod(t_h2_poller *poller, int fd, short events, void *data) {
	struct epoll_event ev;

	if ((poller == NULL) || (fd < 0) || (fd >= poller->reg_size)) {
		return -1;
	}

	if (poller->reg[fd].registered == 0) {
		return -1;
	}

	if ((poller->reg[fd].events == events) && (poller->reg[fd].data == data)) {
		/* Unchanged -- and NO SYSCALL. This is the property the whole
		 * contract rests on: the caller may refresh whenever it is in doubt
		 * instead of reasoning about which edge it is allowed to skip, and a
		 * refresh that changes nothing costs a compare. */
		return 0;
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = h2_poller_to_epoll_events(events);
	ev.data.ptr = data;

	if (epoll_ctl(poller->epfd, EPOLL_CTL_MOD, fd, &ev) == -1) {
		return -1;
	}

	poller->reg[fd].data = data;
	poller->reg[fd].events = events;

	return 0;
}

int h2_poller_del(t_h2_poller *poller, int fd) {
	if (poller == NULL) {
		return -1;
	}

	if ((fd < 0) || (fd >= poller->reg_size) || (poller->reg[fd].registered == 0)) {
		/* Not registered: succeed and do nothing. See h2_poller.h for why
		 * this one is not an error. */
		return 0;
	}

	/* Result deliberately unchecked, and the reason is narrower than it looks.
	 * ENOENT means the kernel no longer holds this descriptor, which is the
	 * state being asked for. EBADF does NOT mean that: epoll drops a
	 * registration only when the last descriptor referring to that open file
	 * description is gone, and this server forks CGI children from other
	 * threads (see the EPOLL_CLOEXEC above) -- one of them, between fork and
	 * exec, keeps the registration alive after this process has closed its
	 * own copy. Calling del before the close is what keeps that from
	 * mattering; called after, no return value here could repair it, because
	 * the entry the kernel still holds is one this process can no longer
	 * name. See h2_poller.h at h2_poller_del for what that costs in each
	 * backend.
	 *
	 * Unchecked either way, because the bookkeeping below must happen
	 * regardless: leave the fd "registered" here and its number can never be
	 * reused. */
	epoll_ctl(poller->epfd, EPOLL_CTL_DEL, fd, NULL);

	poller->reg[fd].registered = 0;
	poller->reg[fd].data = NULL;
	poller->reg[fd].events = 0;
	poller->count--;

	return 0;
}

int h2_poller_count(const t_h2_poller *poller) {
	if (poller == NULL) {
		return 0;
	}

	return poller->count;
}

int h2_poller_wait(t_h2_poller *poller, t_h2_pevent *out, int max, int timeout_ms) {
	struct epoll_event *grown;
	int ready, filled, i;
	short events;

	if ((poller == NULL) || (out == NULL) || (max <= 0) || (timeout_ms < 0)) {
		errno = EINVAL;
		return -1;
	}

	if (poller->events_capacity < max) {
		if ((grown = (struct epoll_event*)realloc(poller->events,
		     (size_t)max * sizeof(struct epoll_event))) == NULL) {
			errno = ENOMEM;
			return -1;
		}
		poller->events = grown;
		poller->events_capacity = max;
	}

	if ((ready = epoll_wait(poller->epfd, poller->events, max, timeout_ms)) <= 0) {
		/* 0 is the timeout, which the loop needs as its idle tick; -1 leaves
		 * errno for the caller, EINTR included. */
		return ready;
	}

	filled = 0;
	for (i = 0; i < ready; i++) {
		if ((events = h2_poller_from_epoll_events(poller->events[i].events)) == 0) {
			continue;
		}
		out[filled].data = poller->events[i].data.ptr;
		out[filled].events = events;
		filled++;
	}

	return filled;
}

void h2_poller_destroy(t_h2_poller *poller) {
	if (poller == NULL) {
		return;
	}

	if (poller->epfd != -1) {
		close(poller->epfd);
	}
	free(poller->reg);
	free(poller->events);
	free(poller);
}

#elif defined(HAVE_KQUEUE)

/* ========================================================================
 *  kqueue(2) backend -- OpenBSD, FreeBSD, macOS
 *
 *  Same contract as epoll, three things translated:
 *
 *  ONE FD IS TWO REGISTRATIONS.  kqueue has no combined interest mask; read
 *  and write are separate filters. Both are registered at add time and the
 *  write one starts DISABLED, so a mask change is EV_ENABLE/EV_DISABLE and
 *  never an add or a delete. That keeps "registered once" literally true.
 *
 *  It does NOT keep h2_poller_mod() to one syscall, and the sentence that
 *  used to claim so was wrong: one filter is one kevent(), so a mod that
 *  moves BOTH bits costs two, and so does one that only changes the data
 *  pointer -- udata rides on each filter separately. Counted, not reasoned:
 *  2 calls for either, against 1 on epoll, and 0 when nothing changed at all
 *  (docs/audit-2026-08/h2poller-audit.md, F3). The caller never pays it:
 *  h2_conn_refresh_interest() keeps HP_IN set and hands over the same
 *  pointer for a connection's whole life, so at most HP_OUT moves.
 *
 *  A DISABLED FILTER REPORTS NOTHING, not even a hangup, and that is where
 *  this backend falls short of rule 3 -- a descriptor whose interest mask is
 *  empty has both filters disabled and goes silent, where poll and epoll would
 *  still report the peer's death. It cannot be repaired here: leaving
 *  EVFILT_READ enabled and dropping HP_IN on the way out spins, because a
 *  readable descriptor fires every round and an event that maps to no bit is
 *  skipped, so the wait returns 0 and is called again immediately. Reporting
 *  HP_IN anyway would hand the caller reads it switched off, which is how
 *  throttling is switched off. The contract was narrowed instead
 *  (h2_poller.h, rule 3): keep HP_IN set on anything whose end matters.
 *
 *  ONE FD CAN COME BACK TWICE.  A connection that is readable AND writable
 *  produces TWO kevents, where poll and epoll produce one entry with both
 *  bits. Handing that through would run the I/O phase twice for the same
 *  connection and would overflow a batch sized from h2_poller_count(). So the
 *  two are COALESCED here into one output entry, and the caller sees exactly
 *  what the other two backends give it. The scratch array is sized for two
 *  kevents per registered descriptor because that is what the kernel may
 *  deliver before coalescing.
 *
 *  EV_EOF IS NOT POLLHUP, and this is the part that is easy to get wrong.
 *  EVFILT_READ sets EV_EOF as soon as the peer closed its WRITE side --
 *  a half close, which poll(2) reports as plain POLLIN with a zero-byte read
 *  and NOT as POLLHUP. Mapping EV_EOF straight to HP_HUP would therefore tear
 *  down connections here that the other two backends keep, which is a
 *  behaviour difference, not a detail. The kernel hands over what is needed to
 *  tell the two apart: on EVFILT_READ, data is the number of bytes still
 *  readable. So EV_EOF with bytes left is HP_IN (there is still something to
 *  read), and only EV_EOF with nothing left is also HP_HUP.
 *
 *  THAT LAST STEP STILL GOES FURTHER THAN POLL DOES, and the sentence that
 *  used to stand here -- "which is the state poll calls a hangup" -- was
 *  wrong. A peer that shut only its write side, with the buffer drained, is
 *  POLLIN and a zero-byte read to poll(2); POLLHUP comes when the connection
 *  is torn down. So this backend reports HP_HUP earlier than the other two,
 *  and the write filter adds HP_OUT | HP_HUP, a pair poll(2) rules out for
 *  itself. Left as it is on purpose: dropping it would align the three by
 *  making THIS one worse, since http2.c closes such a connection at once here
 *  and would otherwise hold the slot until the idle timeout on every BSD. The
 *  difference is written into the contract instead (h2_poller.h, rule 5:
 *  HP_HUP is a hint, and no caller may branch it exclusively).
 *
 *  Level-triggered, so NO EV_CLEAR: the default. The handlers do not read to
 *  EAGAIN, and h2_read_and_process() stops at a partial TLS record on purpose.
 * ======================================================================== */

/* A mask no real interest can equal: the HP_* bits are positive, so -1 says
 * "what the kernel holds for this descriptor is not known here". Written when
 * a change syscall fails halfway; see h2_poller_mod. */
#define H2_POLLER_MASK_UNKNOWN  ((short)-1)

/* One change, applied immediately. Batching them until the next wait would
 * save syscalls, but it would also mean the interest the kernel holds and the
 * interest this module reports could differ for a whole cycle -- and telling
 * those apart is exactly what the contract is about. */
static int h2_poller_change(t_h2_poller *poller, int fd, short filter, unsigned short flags, void *data) {
	struct kevent kev;

	EV_SET(&kev, (uintptr_t)fd, filter, flags, 0, 0, data);

	if (kevent(poller->kq, &kev, 1, NULL, 0, NULL) == -1) {
		return -1;
	}

	return 0;
}

t_h2_poller *h2_poller_create(void) {
	t_h2_poller *poller;

	if ((poller = (t_h2_poller*)calloc(1, sizeof(t_h2_poller))) == NULL) {
		return NULL;
	}

#ifdef HAVE_KQUEUE1
	/* Atomic CLOEXEC in the creating call, like epoll_create1(EPOLL_CLOEXEC)
	 * on the other backend: no window between kqueue() and fcntl() for an
	 * exec on another thread to inherit through, and no after-the-fact call
	 * left that could fail. OpenBSD has kqueue1(O_CLOEXEC) since 7.9,
	 * FreeBSD since 15; the probe is HAVE_KQUEUE1 in CMakeLists.txt. */
	if ((poller->kq = kqueue1(O_CLOEXEC)) == -1) {
		free(poller);
		return NULL;
	}
#else
	if ((poller->kq = kqueue()) == -1) {
		free(poller);
		return NULL;
	}

	/* macOS has neither kqueue1() nor KQUEUE_CLOEXEC, so the flag goes on
	 * afterwards.
	 *
	 * The window between the two calls is not the one the wakeup pipe worries
	 * about: a kqueue descriptor is not inherited by an ordinary fork(2), so a
	 * CGI child forked inside the window has nothing to inherit. That holds
	 * for what this file does; it is not absolute, and FreeBSD's kqueue(2)
	 * names the two ways out -- rfork(2) without RFFDG shares the descriptor
	 * table, and KQUEUE_CPONFORK copies the queue into the child. Hiawatha
	 * uses neither. Measured rather than read: the child gets EBADF on all
	 * three BSDs.
	 *
	 * The fcntl is here anyway, because "not inherited" is a promise about
	 * fork and this process also execs. And it either takes or the poller is
	 * not created: a queue whose descriptor would survive an exec is not the
	 * queue this file promises, so a failure here is a creation failure like
	 * kqueue() itself. */
	if (h2_fd_set_cloexec(poller->kq) == -1) {
		close(poller->kq);
		free(poller);
		return NULL;
	}
#endif

	return poller;
}

int h2_poller_add(t_h2_poller *poller, int fd, short events, void *data) {
	int size;

	if ((poller == NULL) || (fd < 0)) {
		return -1;
	}

	if ((size = h2_poller_grow_table((void**)&poller->reg, poller->reg_size,
	     sizeof(t_h2_poller_reg), fd)) == 0) {
		return -1;
	}
	/* The shared helper zero-fills, and 0 is a valid batch index, so the
	 * "not in the batch" marker has to be written for the new range. */
	while (poller->reg_size < size) {
		poller->reg[poller->reg_size].out_index = -1;
		poller->reg_size++;
	}

	if (poller->reg[fd].registered) {
		/* Already registered. A caller error, and one worth failing on: it
		 * means two connections believe they own this descriptor. */
		return -1;
	}

	if (h2_poller_change(poller, fd, EVFILT_READ,
	     EV_ADD | ((events & HP_IN) ? EV_ENABLE : EV_DISABLE), data) == -1) {
		return -1;
	}
	if (h2_poller_change(poller, fd, EVFILT_WRITE,
	     EV_ADD | ((events & HP_OUT) ? EV_ENABLE : EV_DISABLE), data) == -1) {
		h2_poller_change(poller, fd, EVFILT_READ, EV_DELETE, NULL);
		return -1;
	}

	poller->reg[fd].data = data;
	poller->reg[fd].events = events;
	poller->reg[fd].out_index = -1;
	poller->reg[fd].registered = 1;
	poller->count++;

	return 0;
}

int h2_poller_mod(t_h2_poller *poller, int fd, short events, void *data) {
	short changed;
	bool unknown;

	if ((poller == NULL) || (fd < 0) || (fd >= poller->reg_size)) {
		return -1;
	}

	if (poller->reg[fd].registered == 0) {
		return -1;
	}

	/* A change syscall failed halfway last time, so what the kernel holds for
	 * this descriptor is not known here. EVERY test below has to yield to
	 * this one, including the cheap exit -- a sentinel that only some of them
	 * consult is the same as no sentinel at all (see the failure path). */
	unknown = (poller->reg[fd].events == H2_POLLER_MASK_UNKNOWN);

	if ((unknown == false) && (poller->reg[fd].events == events) && (poller->reg[fd].data == data)) {
		/* Unchanged -- and NO SYSCALL. This is the property the whole
		 * contract rests on: the caller may refresh whenever it is in doubt
		 * instead of reasoning about which edge it is allowed to skip, and a
		 * refresh that changes nothing costs a compare. */
		return 0;
	}

	changed = poller->reg[fd].events ^ events;

	/* udata is carried on every filter, so a changed data pointer has to be
	 * written to both -- otherwise the batch would hand back a stale one from
	 * whichever filter did not change. */
	if (unknown || (changed & HP_IN) || (poller->reg[fd].data != data)) {
		if (h2_poller_change(poller, fd, EVFILT_READ,
		     EV_ADD | ((events & HP_IN) ? EV_ENABLE : EV_DISABLE), data) == -1) {
			poller->reg[fd].events = H2_POLLER_MASK_UNKNOWN;
			return -1;
		}
	}
	if (unknown || (changed & HP_OUT) || (poller->reg[fd].data != data)) {
		if (h2_poller_change(poller, fd, EVFILT_WRITE,
		     EV_ADD | ((events & HP_OUT) ? EV_ENABLE : EV_DISABLE), data) == -1) {
			/* Two filters, two syscalls, and the first one may have gone
			 * through -- so on a failure here the kernel holds a state this
			 * module cannot name any more. Recording the requested mask would
			 * be a lie, and the next refresh would then see "unchanged" and
			 * skip the repair for good: one failed syscall would turn into a
			 * connection that never wakes. So the sentinel goes in, and
			 * `unknown` above makes the next mod rewrite BOTH filters no
			 * matter what it thinks changed.
			 *
			 * That last clause is the whole of it, and it used to be missing.
			 * The sentinel is -1, so every bit is set, and the tests were
			 * `changed & HP_IN` over `changed = sentinel ^ events`: that is
			 * ZERO for exactly the bits the new mask asks for. The repair
			 * rewrote the filters nobody wanted and skipped the ones that
			 * needed it, then cleared the sentinel on the way out -- the
			 * divergence was not healed, it was forgotten. */
			poller->reg[fd].events = H2_POLLER_MASK_UNKNOWN;
			return -1;
		}
	}

	poller->reg[fd].data = data;
	poller->reg[fd].events = events;

	return 0;
}

int h2_poller_del(t_h2_poller *poller, int fd) {
	if (poller == NULL) {
		return -1;
	}

	if ((fd < 0) || (fd >= poller->reg_size) || (poller->reg[fd].registered == 0)) {
		/* Not registered: succeed and do nothing. See h2_poller.h for why
		 * this one is not an error. */
		return 0;
	}

	/* Both results deliberately unchecked, and NOT for the reason the epoll
	 * backend gives. There, EPOLL_CTL_DEL fails only when the kernel has
	 * already forgotten the descriptor. Here there is a second, ordinary case:
	 * a descriptor that was closed is removed from every kqueue automatically,
	 * so EV_DELETE afterwards is ENOENT and means nothing went wrong. The
	 * bookkeeping below must happen either way, or the fd would stay
	 * "registered" here and its number could never be reused. */
	h2_poller_change(poller, fd, EVFILT_READ, EV_DELETE, NULL);
	h2_poller_change(poller, fd, EVFILT_WRITE, EV_DELETE, NULL);

	poller->reg[fd].registered = 0;
	poller->reg[fd].data = NULL;
	poller->reg[fd].events = 0;
	poller->reg[fd].out_index = -1;
	poller->count--;

	return 0;
}

int h2_poller_count(const t_h2_poller *poller) {
	if (poller == NULL) {
		return 0;
	}

	return poller->count;
}

int h2_poller_wait(t_h2_poller *poller, t_h2_pevent *out, int max, int timeout_ms) {
	struct kevent *grown;
	struct timespec ts;
	int want, ready, filled, i, slot, fd;
	short events;

	if ((poller == NULL) || (out == NULL) || (max <= 0) || (timeout_ms < 0)) {
		errno = EINVAL;
		return -1;
	}

	/* Two filters per descriptor may fire in the same round, so the kernel may
	 * hand back twice what the caller sized its batch for. Coalescing happens
	 * below; the scratch has to hold the uncoalesced set. */
	want = 2 * max;
	if (poller->events_capacity < want) {
		if ((grown = (struct kevent*)realloc(poller->events,
		     (size_t)want * sizeof(struct kevent))) == NULL) {
			errno = ENOMEM;
			return -1;
		}
		poller->events = grown;
		poller->events_capacity = want;
	}

	ts.tv_sec = timeout_ms / 1000;
	ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;

	if ((ready = kevent(poller->kq, NULL, 0, poller->events, want, &ts)) <= 0) {
		/* 0 is the timeout, which the loop needs as its idle tick; -1 leaves
		 * errno for the caller, EINTR included. */
		return ready;
	}

	filled = 0;
	for (i = 0; i < ready; i++) {
		fd = (int)poller->events[i].ident;
		events = 0;

		if (poller->events[i].flags & EV_ERROR) {
			events |= HP_ERR;
		} else if (poller->events[i].filter == EVFILT_READ) {
			events |= HP_IN;
			/* EV_EOF with nothing left to read is what poll calls POLLHUP;
			 * EV_EOF with bytes still queued is a half close and stays a
			 * plain readable event. See the block comment above. */
			if ((poller->events[i].flags & EV_EOF) && (poller->events[i].data == 0)) {
				events |= HP_HUP;
			}
		} else if (poller->events[i].filter == EVFILT_WRITE) {
			events |= HP_OUT;
			if (poller->events[i].flags & EV_EOF) {
				events |= HP_HUP;
			}
		}

		if (events == 0) {
			continue;
		}

		/* Coalesce: one output entry per descriptor, mask ORed -- what poll
		 * and epoll deliver. */
		if ((fd >= 0) && (fd < poller->reg_size) && (poller->reg[fd].out_index >= 0)) {
			out[poller->reg[fd].out_index].events |= events;
			continue;
		}

		if (filled >= max) {
			continue;
		}

		slot = filled;
		out[slot].data = poller->events[i].udata;
		out[slot].events = events;
		filled++;

		if ((fd >= 0) && (fd < poller->reg_size)) {
			poller->reg[fd].out_index = slot;
		}
	}

	/* Clear the batch markers. Over the kevents rather than over reg[], so the
	 * cost is O(ready) and not O(largest fd ever seen). */
	for (i = 0; i < ready; i++) {
		fd = (int)poller->events[i].ident;
		if ((fd >= 0) && (fd < poller->reg_size)) {
			poller->reg[fd].out_index = -1;
		}
	}

	return filled;
}

void h2_poller_destroy(t_h2_poller *poller) {
	if (poller == NULL) {
		return;
	}

	if (poller->kq != -1) {
		close(poller->kq);
	}
	free(poller->reg);
	free(poller->events);
	free(poller);
}

#else /* neither epoll nor kqueue */

/* ========================================================================
 *  poll(2) backend
 *
 *  The set is held as the pollfd array the event loop used to rebuild for
 *  itself, plus a parallel array of the caller's data pointers, plus an
 *  fd-indexed map so that add/mod/del are O(1) rather than a scan.  Without
 *  that map the per-cycle interest refresh would be O(n^2), which is worse
 *  than the rebuild it replaces.
 *
 *  Removal swaps with the last entry, exactly as h2_remove_connection() does
 *  on the connection array.  Since both are kept in step -- entry i+1 here is
 *  connection i there, the wakeup pipe holding index 0 -- the two arrays stay
 *  in the same order and a batch is delivered in the same sequence the old
 *  index loop walked.  Nothing depends on that; it is recorded because it is
 *  what makes this step's numbers comparable one for one.
 *
 *  This is the fallback backend, and since step 4 that is all it is:
 *  everything with neither epoll nor kqueue. On this fork's four test
 *  platforms nothing selects it -- Linux takes epoll, the three BSDs take
 *  kqueue -- which is exactly why tests/h2_poller compiles this file a second
 *  time against a config.h that has neither, and runs its cases against the
 *  result. A backend no machine here compiles is a backend nobody would
 *  notice breaking.
 * ======================================================================== */

#define H2_POLLER_INITIAL_CAPACITY   16

static short h2_poller_to_poll_events(short events) {
	short result = 0;

	if (events & HP_IN) {
		result |= POLLIN;
	}
	if (events & HP_OUT) {
		result |= POLLOUT;
	}

	/* HP_HUP and HP_ERR are results, never interests: poll(2) reports
	 * POLLHUP/POLLERR whether or not they were asked for, and passing them in
	 * events is ignored.  Dropping them here keeps the registered mask equal
	 * to what the event loop built by hand before. */

	return result;
}

static short h2_poller_from_poll_events(short revents) {
	short result = 0;

	if (revents & POLLIN) {
		result |= HP_IN;
	}
	if (revents & POLLOUT) {
		result |= HP_OUT;
	}
	if (revents & POLLHUP) {
		result |= HP_HUP;
	}
	if (revents & POLLERR) {
		result |= HP_ERR;
	}

	/* POLLNVAL is deliberately NOT mapped.  The event loop has never acted on
	 * it: its handler tests POLLIN, POLLOUT and POLLHUP|POLLERR, so a
	 * descriptor that came back only invalid was entered and left alone.  An
	 * unmapped bit yields an empty mask here, the entry is not reported, and
	 * the outcome is the same nothing.  Turning it into HP_ERR would close
	 * such a connection -- defensible, but a behaviour change, and this step
	 * is supposed to have none. */

	return result;
}

static bool h2_poller_reserve_entry(t_h2_poller *poller) {
	struct pollfd *new_fds;
	void **new_data;
	int new_cap;

	if (poller->count < poller->capacity) {
		return true;
	}

	if ((poller->capacity != 0) && (poller->capacity > INT_MAX / 2)) {
		return false;
	}
	new_cap = (poller->capacity == 0) ? H2_POLLER_INITIAL_CAPACITY : poller->capacity * 2;

	if ((new_fds = (struct pollfd*)realloc(poller->fds, (size_t)new_cap * sizeof(struct pollfd))) == NULL) {
		return false;
	}
	poller->fds = new_fds;

	if ((new_data = (void**)realloc(poller->data, (size_t)new_cap * sizeof(void*))) == NULL) {
		/* fds[] is already the larger block.  Leaving it that way is
		 * harmless -- capacity below still names the pair's usable size, so
		 * the next attempt simply retries the same growth. */
		return false;
	}
	poller->data = new_data;

	poller->capacity = new_cap;

	return true;
}

t_h2_poller *h2_poller_create(void) {
	t_h2_poller *poller;

	if ((poller = (t_h2_poller*)calloc(1, sizeof(t_h2_poller))) == NULL) {
		return NULL;
	}

	return poller;
}

int h2_poller_add(t_h2_poller *poller, int fd, short events, void *data) {
	int size;

	if ((poller == NULL) || (fd < 0)) {
		return -1;
	}

	if ((size = h2_poller_grow_table((void**)&poller->slot, poller->slot_size,
	     sizeof(int), fd)) == 0) {
		return -1;
	}
	poller->slot_size = size;

	if (poller->slot[fd] != 0) {
		/* Already registered.  A caller error, and one worth failing on: it
		 * means two connections believe they own this descriptor. */
		return -1;
	}

	if (h2_poller_reserve_entry(poller) == false) {
		return -1;
	}

	poller->fds[poller->count].fd = fd;
	poller->fds[poller->count].events = h2_poller_to_poll_events(events);
	poller->fds[poller->count].revents = 0;
	poller->data[poller->count] = data;
	poller->slot[fd] = poller->count + 1;
	poller->count++;

	return 0;
}

int h2_poller_mod(t_h2_poller *poller, int fd, short events, void *data) {
	short want;
	int index;

	if ((poller == NULL) || (fd < 0) || (fd >= poller->slot_size)) {
		return -1;
	}

	if (poller->slot[fd] == 0) {
		return -1;
	}
	index = poller->slot[fd] - 1;

	want = h2_poller_to_poll_events(events);

	if ((poller->fds[index].events == want) && (poller->data[index] == data)) {
		/* Unchanged.  This is the common case by a wide margin, and it costing
		 * nothing is what lets the caller refresh liberally instead of
		 * reasoning about which edges it may skip. */
		return 0;
	}

	poller->fds[index].events = want;
	poller->data[index] = data;

	return 0;
}

int h2_poller_del(t_h2_poller *poller, int fd) {
	int index, last;

	if (poller == NULL) {
		return -1;
	}

	if ((fd < 0) || (fd >= poller->slot_size) || (poller->slot[fd] == 0)) {
		/* Not registered: succeed and do nothing.  See h2_poller.h for why
		 * this one is not an error. */
		return 0;
	}
	index = poller->slot[fd] - 1;

	last = poller->count - 1;
	if (index != last) {
		poller->fds[index] = poller->fds[last];
		poller->data[index] = poller->data[last];
		poller->slot[poller->fds[index].fd] = index + 1;
	}

	poller->slot[fd] = 0;
	poller->count--;

	return 0;
}

int h2_poller_count(const t_h2_poller *poller) {
	if (poller == NULL) {
		return 0;
	}

	return poller->count;
}

int h2_poller_wait(t_h2_poller *poller, t_h2_pevent *out, int max, int timeout_ms) {
	int ready, filled, i;
	short events;

	if ((poller == NULL) || (out == NULL) || (max <= 0) || (timeout_ms < 0)) {
		errno = EINVAL;
		return -1;
	}

	for (i = 0; i < poller->count; i++) {
		poller->fds[i].revents = 0;
	}

	if ((ready = poll(poller->fds, (nfds_t)poller->count, timeout_ms)) <= 0) {
		/* 0 is the timeout, which the loop needs as its idle tick; -1 leaves
		 * errno for the caller, EINTR included. */
		return ready;
	}

	filled = 0;
	for (i = 0; (i < poller->count) && (filled < max); i++) {
		if (poller->fds[i].revents == 0) {
			continue;
		}

		if ((events = h2_poller_from_poll_events(poller->fds[i].revents)) == 0) {
			continue;
		}

		out[filled].data = poller->data[i];
		out[filled].events = events;
		filled++;
	}

	/* filled < ready is possible only through the unmapped-bit case above;
	 * filled == max would mean the caller sized its batch below
	 * h2_poller_count(), and the remainder would come back next round because
	 * the backend is level-triggered. */

	return filled;
}

void h2_poller_destroy(t_h2_poller *poller) {
	if (poller == NULL) {
		return;
	}

	free(poller->fds);
	free(poller->data);
	free(poller->slot);
	free(poller);
}

#endif /* backend selection */

#endif /* ENABLE_HTTP2 */
