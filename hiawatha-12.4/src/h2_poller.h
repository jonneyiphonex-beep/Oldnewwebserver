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

#ifndef _H2_POLLER_H
#define _H2_POLLER_H

#include "config.h"

#ifdef ENABLE_HTTP2

/* I/O multiplexing for the HTTP/2 event loop.
 *
 * One instance per event loop.  The loop registers each descriptor ONCE and
 * afterwards only says what it wants to hear about; the poller owns the set
 * and hands back the ready ones.
 *
 * Three backends, one per platform, chosen at COMPILE time and never at run
 * time: epoll where epoll_create1 exists, else kqueue where kqueue does, else
 * poll(2).  poll is the fallback rather than the plain case -- it rebuilds
 * nothing and is exactly the loop that stood in http2.c before the interface
 * was cut out, which is what made the first step comparable one for one.
 * h2_poller_backend() names the one this build got.
 *
 * THE CONTRACT EVERY BACKEND MUST SATISFY
 *
 * 1. Level-triggered.  A descriptor that is readable and stays unread is
 *    reported again on the next wait.  epoll gets no EPOLLET, kqueue gets no
 *    EV_CLEAR -- the loop's handlers do not read to EAGAIN and would hang.
 *
 * 2. The interest lives in the poller, not in the caller.  With poll(2) the
 *    mask is re-read out of this module on every wait, so a stale mask is
 *    impossible.  With epoll AND kqueue it sits in the KERNEL and only
 *    h2_poller_mod() moves it: a forgotten mod is a connection that never
 *    wakes again -- on both of them, and on three of this fork's four test
 *    platforms it is kqueue that would swallow it, not epoll.  That
 *    is why mod is specified as CHEAP AND IDEMPOTENT below -- calling it
 *    whenever the state might have changed has to be the affordable option,
 *    or the contract will be broken by whoever is in a hurry.
 *
 * 3. HP_HUP / HP_ERR may be reported without ever having been asked for.
 *    They are not part of the interest mask; requesting them is not an error
 *    and has no effect.
 *
 *    BUT ONLY WHILE SOME INTEREST IS SET.  A descriptor registered with an
 *    EMPTY mask can report nothing at all on kqueue, not even the death of
 *    its peer: the two filters carry the result bits, and a filter that is
 *    EV_DISABLEd "will not return it" (kevent(2)).  epoll does report a
 *    hangup on a mask of zero, and so does poll(2) on Linux, OpenBSD and
 *    FreeBSD -- but NOT on macOS, where an empty mask is as silent as
 *    kqueue's (measured on all four; the Darwin man page promises the
 *    opposite, calling POLLHUP "output only, and ignored if present in the
 *    input events bitmask").  It is written down rather than fixed -- see
 *    h2_poller.c at the EV_DISABLE for what the attempt costs.  Keep HP_IN
 *    set on anything whose end you want to hear about; http2.c does
 *    (h2_conn_refresh_interest starts from HP_IN), which is why no
 *    connection is parked mute today.
 *
 * 4. Between h2_poller_wait() and the end of processing the batch it filled,
 *    NO descriptor may be removed from the poller.  The events carry the
 *    caller's data pointer, and a batch entry for a connection freed earlier
 *    in the same batch is a use-after-free.  http2.c honours this by removing
 *    connections only in h2_check_timeouts(), which runs after the batch --
 *    the same discipline the array-index loop needed before, for the same
 *    reason (h2_remove_connection swaps with the last element).
 *
 * 5. HP_HUP IS A HINT, NOT A VERDICT, and it does not mean the same thing on
 *    all three -- nor, for poll, the same thing on all four platforms.  Read
 *    it as "this peer will send nothing more", never as "this peer is gone"
 *    and never as "writing is pointless":
 *
 *      kqueue reports it at a HALF close -- the peer shut its write side and
 *      nothing is left to read.  With bytes still queued it does not (the
 *      EV_EOF/data split below).
 *      epoll reports it only once the connection is torn down; the half
 *      close reaches the caller as a readable descriptor whose read returns
 *      zero.
 *      poll IS NOT ONE BEHAVIOUR, and the sentence that used to stand here
 *      treated it as one.  On Linux, OpenBSD and FreeBSD it answers a half
 *      close like epoll, with a plain readable descriptor.  On macOS it
 *      answers POLLIN | POLLHUP -- at the half close, and ALSO while bytes
 *      are still queued, which is EARLIER than the kqueue backend on the
 *      same machine.  (Darwin's poll(2) is itself built on kqueue, so the
 *      "neutral reference" reading of this backend does not hold there.)
 *
 *      THE PAIR HP_OUT | HP_HUP OCCURS, on kqueue, on epoll and on Linux's
 *      poll -- all measured.  The BSD and macOS poll(2) man pages call
 *      POLLOUT and POLLHUP "mutually exclusive", and this file used to quote
 *      that as if it bound every poll(2); it binds those platforms' own.
 *
 *    So: never branch HP_HUP exclusively against HP_IN or HP_OUT (no
 *    else-if), and never let it replace the zero-byte read as the way a
 *    peer's end is learned.  http2.c handles the three bits independently
 *    and reaches the same state either way, which is the only reason the
 *    difference costs nothing today.
 */

#include <stdbool.h>

/* Event bits.  Deliberately NOT the POLL* constants: on epoll and kqueue
 * these have to be translated anyway, and a mask that happens to be a
 * pollfd.events on one platform invites passing one straight through. */
#define HP_IN    0x01   /* readable                        (interest + result) */
#define HP_OUT   0x02   /* writable                        (interest + result) */
#define HP_HUP   0x04   /* peer sends no more  (result only, see rule 5)       */
#define HP_ERR   0x08   /* error condition on the socket   (result only)       */

typedef struct type_h2_poller t_h2_poller;

typedef struct {
	void  *data;      /* whatever was handed to add/mod for this descriptor */
	short  events;    /* HP_* bits that fired */
} t_h2_pevent;

/* Create an empty poller.  Backends that need a descriptor of their own
 * (epoll, kqueue) create it close-on-exec: Hiawatha forks CGI children from
 * other threads, and every open descriptor that is not close-on-exec is
 * inherited.  The poll backend has no such descriptor.
 * Returns NULL on failure. */
t_h2_poller *h2_poller_create(void);

/* Register fd with the given interest.  Registering an fd that is already
 * registered is a caller error and fails.  Returns 0 or -1. */
int h2_poller_add(t_h2_poller *poller, int fd, short events, void *data);

/* Change interest and/or data for a registered fd.  CHEAP AND IDEMPOTENT:
 * when neither differs from what is already registered, this does no work at
 * all (and, on epoll, issues no syscall).  Failing on an unregistered fd is
 * deliberate -- see h2_poller_del for why del is the asymmetric one.
 * Returns 0 or -1. */
int h2_poller_mod(t_h2_poller *poller, int fd, short events, void *data);

/* Deregister fd.  Removing an fd that is NOT registered succeeds and does
 * nothing.  That asymmetry to add/mod is on purpose: the caller deregisters
 * from h2_close_connection(), which also runs for connections that never
 * reached the poller (rejected while still pending), and a single
 * unconditional call there is worth more than a conditional one that can be
 * forgotten.  Returns 0 or -1.
 *
 * MUST be called BEFORE the descriptor is closed.  A closed fd number is
 * reused immediately, and a stale registration would then belong to the next
 * connection that draws it.
 *
 * That is not one rule with one consequence: closing first fails DIFFERENTLY
 * in each backend, and none of the three is a diagnosis anyone would enjoy.
 *
 *   poll   the closed descriptor answers POLLNVAL, which is deliberately not
 *          mapped to any HP_* bit -- so the wait fills nothing, returns 0, and
 *          poll(2) returns instantly on the next call as well.  The idle tick
 *          becomes a busy loop at full CPU, for good, and writes no line
 *          anywhere.
 *   epoll  the registration can OUTLIVE the close.  It is dropped when the
 *          last descriptor referring to that open file description goes, and
 *          this server forks CGI children from other threads -- a child
 *          between fork and exec holds one.  epoll_wait() then hands back
 *          events carrying the data pointer of a connection that has been
 *          freed.
 *   kqueue heals: closing a descriptor removes its kevents (kqueue(2)), and
 *          the later EV_DELETE is a harmless ENOENT.
 *
 * So the order is not a tidiness rule and the poll backend is not the mild
 * case.  http2.c gets it right in h2_close_connection(), which deregisters
 * before close_socket() and says why at the call. */
int h2_poller_del(t_h2_poller *poller, int fd);

/* Number of registered descriptors.  The caller sizes its event batch from
 * this: one wait may report every one of them, and a batch too small silently
 * drops the rest until the next round. */
int h2_poller_count(const t_h2_poller *poller);

/* Wait up to timeout_ms and fill out[0..max-1] with the ready descriptors.
 * Returns how many were filled, or -1 with errno set (EINTR is the caller's
 * to handle, as it was with poll()).  Entries whose only ready bit has no
 * HP_* meaning are not reported.
 *
 * timeout_ms MUST be >= 0; a negative value is EINVAL in every backend, and
 * deliberately NOT poll(2)'s "-1 blocks forever".  Left alone, the same
 * argument produced three behaviours: poll and epoll would have waited
 * without end, kqueue rejects the timespec that arithmetic makes of it.  The
 * loop needs its idle tick -- a wait that never returns is a loop that stops
 * checking timeouts, and it is silent, where the error is not.  So the one
 * behaviour they can all share is the loud one. */
int h2_poller_wait(t_h2_poller *poller, t_h2_pevent *out, int max, int timeout_ms);

void h2_poller_destroy(t_h2_poller *poller);

/* Which backend this build got: "epoll", "kqueue" or "poll". For reports and
 * for tests that have to say which one they exercised — a suite that cannot
 * name the backend it ran against proves nothing about the other one, and
 * tests/h2_poller refuses to believe its own cases until this agrees with
 * what it built. Three values, so a caller comparing against two of them
 * silently drops a whole platform family. */
const char *h2_poller_backend(void);

#endif /* ENABLE_HTTP2 */

#endif
