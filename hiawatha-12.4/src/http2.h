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

#ifndef _HTTP2_H
#define _HTTP2_H

#include "config.h"

#ifdef ENABLE_HTTP2

#include <stdint.h>
#include <netinet/in.h>
#include <nghttp2/nghttp2.h>
#include "global.h"
#include "session.h"

#define H2_MAX_CONCURRENT_STREAMS   128    /* default; overridden by H2MaxConcurrentStreams */
#define H2_MAX_QUEUED_PER_CONN      256    /* per-connection dispatch queue depth;
                                            * 2x H2_MAX_CONCURRENT_STREAMS to absorb
                                            * burst completions between drain cycles */
#define H2_READ_BUFFER_SIZE        (16 * KILOBYTE)
#define H2_MAX_HEADER_VALUE_LEN    8192
#define H2_MAX_HEADER_LIST_SIZE   65536
#define H2_IDLE_TIMEOUT            300    /* seconds */
#define H2_CLOSING_TIMEOUT          30    /* seconds: max wait for pending workers */
#define H2_DEATH_DRAIN_TIMEOUT      10    /* seconds: response-queue settle on the
                                           * loop thread's own way out -- after a
                                           * death no shutdown may follow for days,
                                           * and until the responses drain the
                                           * zombies hold their memory */
#define H2_INITIAL_CONN_CAPACITY    64
/* Per-stream response buffer limit.  The HTTP/2 path BUFFERS every response
 * whole before submitting it (send.c collects, h2_submit_response_from_buf
 * parses and hands the body to nghttp2 out of memory), so this cap is the
 * biggest file the server can deliver over h2 -- a response above it is
 * reset before its first body byte, with a log line naming both counts.
 * The price of the design is memory: RSS grows by roughly the response size
 * for the lifetime of the transfer, per concurrent large stream.
 *
 * 1536 MB, not more, for a reason that is arithmetic rather than taste:
 * the submit path measures the buffer with strnstr(), whose fallback
 * prototype (alternative.h) takes an int length, and response_size is cast
 * to int there -- the cap must stay below INT_MAX (2048 MB) or the cast
 * turns negative.  1536 leaves headroom above the 1 GB class of file this
 * tree is expected to serve while keeping every such cast valid. */
#define H2_MAX_RESPONSE_SIZE      ((size_t)1536 * MEGABYTE)
#define H2_MAX_CONNECTIONS        1024    /* max concurrent HTTP/2 connections in event loop */
#define H2_MAX_WORKERS            2048    /* max concurrent H2 worker threads;
                                           * prevents pthread_create() exhaustion
                                           * under burst load (100c × 32 streams).
                                           * must be high enough for steady-state
                                           * throughput, low enough to prevent
                                           * OS thread limit exhaustion */

/* How many HTTP/1.1 connections one HTTP/2 connection stands for when
 * BanOnFlooding counts requests.  The counter lives per connection, and an
 * HTTP/1.1 browser spreads a page across several connections while HTTP/2
 * multiplexes everything onto one -- the same configured number would
 * therefore hit an HTTP/2 client about six times harder than the HTTP/1.1
 * behaviour it was written for.
 *
 * Six, because it is the connection ceiling all major engines document for
 * themselves (checked against primary sources, 2026-08-12): Chromium allows
 * 6 connections per host (net/socket/client_socket_pool_manager.cc,
 * g_max_sockets_per_group), Firefox defaults
 * network.http.max-persistent-connections-per-server to 6 (all.js), Apple's
 * URL loading system documents 6 (httpMaximumConnectionsPerHost), and Edge
 * shares Chromium's network stack.  That is browser PRACTICE, not a
 * standard: RFC 2616 (8.1.4) once said a single-user client SHOULD NOT go
 * beyond 2 connections, and RFC 7230 (6.4) withdrew any number.  Using the
 * ceiling rather than a measured value is deliberate -- a browser that opens
 * fewer connections than its ceiling is treated more leniently over HTTP/2
 * than over HTTP/1.1, never more strictly, which is the right error
 * direction for a ban. */
#define H2_FLOOD_CONNECTION_FACTOR   6

typedef struct type_http2_stream {
	int32_t         stream_id;

	/* Pseudo-headers from HPACK */
	char            *method;
	char            *path;
	char            *authority;
	char            *scheme;

	/* Regular headers collected during HPACK decode */
	t_http_header   *headers;
	size_t          header_list_size;

	/* Request body */
	char            *body;
	size_t          body_size;
	size_t          body_capacity;

	/* Stream state */
	bool            headers_complete;
	bool            request_complete;
	bool            body_too_large;   /* body exceeded max_request_size — RST'd, do not dispatch */

	struct type_http2_stream *next;
} t_http2_stream;

/* Opaque here: the structure lives in http2.c and nothing outside it may
 * reach into a shard. */
struct type_h2_shard;

typedef struct type_http2_connection {
	nghttp2_session   *ng_session;
	t_session         *base_session;    /* TLS connection, socket, binding, config */

	/* The shard that owns this connection, set once at accept time and never
	 * changed: everything per-loop -- the connection array, the response
	 * queue, the wakeup pipe, the poller -- is reached through it.  A
	 * connection never migrates, so this pointer is write-once. */
	struct type_h2_shard *shard;

	t_http2_stream    *streams;
	int               active_streams;

	/* Event-loop fields */
	bool              closing;
	bool              client_removed; /* client record already released */
	bool              goaway_booked;  /* a protocol error was already booked for this connection (BanOnGarbage) */
	bool              write_blocked;  /* mbedtls returned WANT_WRITE — needs POLLOUT */
	time_t            created;        /* connection accept time — absolute first-request deadline */
	time_t            last_activity;
	time_t            throttle_until;  /* suppress POLLOUT until this time (timer throttle, not socket back-pressure) */
	time_t            closing_since;  /* when closing was first set */
	int               pending_requests;
	int               inflight_workers;  /* workers currently dispatched for this conn */
	int               requests_served;  /* total streams completed on this connection */

	/* BanOnFlooding, the h2 side (process_response_queue).  The window starts
	 * at connection accept and restarts after a verdict; the count is answered
	 * requests inside the window.  Both live on the connection and are touched
	 * only by the event loop thread. */
	time_t            flooding_timer;
	int               flood_requests;

	/* ChallengeClient, the h2 side.  The stream a challenge was answered on,
	 * 0 while none has been.  HTTP/1.1 refuses a client that ignores the
	 * challenge by counting requests on the connection (session->kept_alive,
	 * challenge.c); the HTTP/2 worker session is zeroed per request, so that
	 * counter is always 1 there and the refusal could never fire.  The
	 * decision is made on the ORDER of stream ids instead of on a count:
	 * a cookieless request on a stream ABOVE this one had the challenge
	 * before it opened and is refused; one at or below it may have been in
	 * flight when the challenge went out and is answered with a challenge of
	 * its own.
	 *
	 * Read and written with the atomic builtins: several streams of one
	 * connection are dispatched to DIFFERENT worker threads (h2_enqueue_request
	 * -> start_worker per item), so this is the one field of this struct that
	 * workers touch, and they touch it concurrently. */
	int32_t           challenge_stream_id;

	/* The highest stream id this connection had RECEIVED at any point, set by
	 * the event loop thread in on_begin_headers_callback() before the request
	 * is queued for a worker.  h2_challenge_answered() publishes THIS value as
	 * the mark, not the stream it was itself serving.
	 *
	 * Without it the mark is racy in one direction only, and that direction is
	 * the expensive one: a browser opens streams 1..15 in one burst, the worker
	 * for stream 1 publishes the mark 1 while the worker for stream 15 is still
	 * ahead of its own comparison, and stream 15 then reads 15 > 1 and bans a
	 * client that never saw a challenge.  Every stream that was already
	 * received when the challenge was answered is at or below this value, so
	 * none of them can clear the mark; only a stream opened afterwards can.
	 *
	 * Written by the event loop thread of the owning shard, read by workers --
	 * atomic builtins for the same reason as the field above. */
	int32_t           highest_stream_id;

	/* Dispatch queue: completed requests waiting for worker threads.
	 * Singly-linked FIFO via work_item->next.  Items are enqueued by
	 * on_frame_recv_callback() and drained by h2_drain_dispatch_queue().
	 * Only the event loop thread accesses these — no mutex needed.
	 * Flushed (freed without dispatch) on connection close and shutdown.
	 */
	struct type_h2_work_item *queue_head;
	struct type_h2_work_item *queue_tail;
	int               queued_count;
} t_http2_connection;

struct type_h2_response_item;  /* forward decl: preallocated response (see below) */

/* Work item: event loop dispatches completed request to worker thread */
typedef struct type_h2_work_item {
	t_http2_connection  *conn;
	int32_t             stream_id;

	/* Deep-copies from the stream */
	char                *method;
	char                *path;
	char                *authority;
	t_http_header       *headers;
	char                *body;
	size_t              body_size;

	/* Response item preallocated at clone time so the worker can ALWAYS
	 * return a response (and thus a pending_requests decrement) even under
	 * memory pressure — no allocation on the worker's terminal path.
	 * Ownership moves to the response queue when the worker enqueues it. */
	struct type_h2_response_item *response;

	/* Read-only references shared with event loop */
	t_config            *config;
	t_binding           *binding;
	t_ip_addr           ip_address;
	in_port_t           remote_port;

	const char          *tls_version;
	const char          *tls_cipher;

	struct type_h2_work_item *next;
} t_h2_work_item;

/* Response item: worker returns completed response to event loop */
typedef struct type_h2_response_item {
	t_http2_connection  *conn;

	/* Which shard's response queue this belongs in.  Carried on the item
	 * rather than derived through conn on every push, and set at creation
	 * time from the connection that caused the item. */
	struct type_h2_shard *shard;

	int32_t             stream_id;

	/* Buffered HTTP/1.1 response (ownership transferred).  response_truncated
	 * says send.c gave up buffering it (H2_MAX_RESPONSE_SIZE, or no memory):
	 * the buffer is then not the whole response and must not be sent as one. */
	char                *response_buf;
	size_t              response_size;
	bool                response_truncated;

	/* Log data for deferred logging */
	int                 return_code;
	bool                log_request;
	off_t               bytes_sent;
	char                *log_uri;
	t_req_method        request_method;

	/* Per-directory throttle discovered by the worker.  Applied to
	 * conn->base_session->throttle by the EVENT LOOP in process_response_queue,
	 * never by the worker — the event loop is the only thread that reads it in
	 * h2_send_callback, so a worker-side write would be a data race. */
	long                throttle;

	struct type_h2_response_item *next;
} t_h2_response_item;

/* Event loop API */
int  h2_event_loop_init(t_config *config);
void h2_event_loop_shutdown(void);
void h2_graceful_shutdown(int timeout_seconds);
int  h2_event_loop_add_connection(t_session *session);

/* Worker-facing function: process a dispatched H2 request */
void h2_worker_process(t_h2_work_item *item);

/* ChallengeClient over HTTP/2 -- see challenge_stream_id above. Both are
 * called from a worker thread, with the session of the request being served. */
bool h2_challenge_had_its_chance(t_session *session);
void h2_challenge_answered(t_session *session);

#endif /* ENABLE_HTTP2 */

#endif
