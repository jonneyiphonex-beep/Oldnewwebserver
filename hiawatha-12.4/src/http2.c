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

#include <sys/types.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <pthread.h>
#include <nghttp2/nghttp2.h>
#include "global.h"
#include "http2.h"
#include "h2_poller.h"
#include "session.h"
#include "http.h"
#include "send.h"
#include "tls.h"
#include "log.h"
#include "client.h"
#include "workers.h"
#include "alternative.h"
#include "liblist.h"
#include "libstr.h"
#include "monitor.h"
#include "memdbg.h"

/* Maximum number of response headers we parse from the buffered HTTP/1.1 output */
#define H2_MAX_RESPONSE_HEADERS 64

/* One HTTP/2 event loop shard: what used to be the module-level singleton.
 * H2EventLoops of these exist (default 1), each with its own thread, poller,
 * wakeup pipe and connection array.  A connection is assigned to one shard at
 * accept time and never migrates, so everything below the mutexes is still
 * touched by exactly one loop thread -- the sharding changes who owns the
 * state, not the locking rules within it. */
typedef struct type_h2_shard {
	pthread_t           thread;
	int                 index;          /* position in h2_shards[], for log lines */
	int                 wakeup_pipe[2];
	volatile bool       running;
	volatile bool       thread_started; /* pthread_create() succeeded -- the
	                                     * shutdown guard: running is cleared by
	                                     * a loop that dies, so it cannot answer
	                                     * "is there a thread to join" */

	/* I/O multiplexing (h2_poller.c).  Holds the wakeup pipe's read end under
	 * the data pointer NULL, and every established connection under its own
	 * t_http2_connection*.  Created before the loop thread and touched only by
	 * it afterwards -- add from process_pending_connections(), del from
	 * h2_close_connection(), both of which run on the loop thread.
	 * No mutex, for the same reason the connection array itself has none. */
	t_h2_poller        *poller;

	/* Event batch handed to h2_poller_wait().  Lives across cycles so the
	 * common case allocates nothing; sized from h2_poller_count() at the top
	 * of each cycle, since one wait may report every registered descriptor. */
	t_h2_pevent        *events;
	int                 events_capacity;

	/* Connection array (protected by conn_mutex) */
	t_http2_connection  **connections;
	int                 conn_count;
	int                 conn_capacity;
	pthread_mutex_t     conn_mutex;

	/* Pending connection queue: new connections waiting to be added */
	t_http2_connection  **pending_conns;
	int                 pending_count;
	int                 pending_capacity;

	/* Response queue (workers push, event loop pops) */
	t_h2_response_item *response_head;
	t_h2_response_item *response_tail;
	pthread_mutex_t     response_mutex;

	/* Zombie connections: closed but still have pending worker responses.
	 * We keep them alive (not free'd) until all workers have finished
	 * and their responses have been drained from the queue.  This prevents
	 * use-after-free when a connection is force-closed (H2_CLOSING_TIMEOUT)
	 * while workers still hold item->conn pointers.
	 */
	t_http2_connection  **zombies;
	int                 zombie_count;
	int                 zombie_capacity;

	t_config            *config;

	/* Graceful shutdown: drain pending requests before exit.
	 * These fields are written by the main/signal thread in
	 * h2_graceful_shutdown() and read by the event loop thread. volatile
	 * is not thread synchronization -- it orders nothing and the compiler
	 * is free to tear the access -- so they are read and written with the
	 * atomic builtins: __atomic_load_n/__atomic_store_n, not the __sync
	 * builtins the int counters use -- GCC rejects __sync on a _Bool
	 * ("operand type volatile _Bool * is incompatible") while clang
	 * accepts it, so a __sync form builds on macOS and fails on every
	 * GCC platform. volatile is kept only because the builtins take a
	 * volatile-qualified pointer here.
	 */
	volatile bool       draining;
	volatile bool       goaway_sent;
	volatile time_t     drain_deadline;
	volatile bool       shutdown_done;  /* guard against double pthread_join */

	/* Workers in flight for THIS shard's connections.  The process-wide
	 * h2_active_workers below still caps the pool; this one exists so a
	 * shard's shutdown waits for its own workers instead of a global count
	 * that other, still-dispatching shards keep above zero. */
	volatile int        active_workers;
} t_h2_shard;

typedef struct {
	const char *data;
	size_t length;
	size_t offset;
	char *response_buf;   /* owns the full response buffer */
} t_h2_data_source;

/* Non-blocking TLS read for the event loop.
 * Unlike tls_receive(), this does NOT loop on WANT_READ.  A single
 * mbedtls_ssl_read() call is made.  If the TLS record is incomplete
 * (WANT_READ), we return 0 so the event loop can continue servicing
 * other connections and come back when poll() fires again.
 */
static int h2_tls_receive(mbedtls_ssl_context *context, char *buffer, unsigned int maxlength) {
	int result;

	result = mbedtls_ssl_read(context, (unsigned char*)buffer, maxlength);
	if ((result == MBEDTLS_ERR_SSL_WANT_READ) ||
	    (result == MBEDTLS_ERR_SSL_WANT_WRITE)) {
		return 0;  /* Incomplete TLS record — come back later */
	}
	if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
		return -1;  /* Peer sent TLS close_notify — connection is done */
	}
	if (result <= 0) {
		/* result == 0: TCP EOF without TLS close_notify (abrupt disconnect)
		 * result < 0:  TLS error (CONN_RESET, etc.)
		 * Both mean the connection should be closed.
		 */
		return -1;
	}

	return result;
}

/* Configure socket for the event loop.
 *
 * O_NONBLOCK: required for correct EAGAIN handling with mbedTLS.
 *   mbedTLS net_would_block() only recognises EAGAIN on non-blocking
 *   sockets (checks O_NONBLOCK via fcntl).  With SO_SNDTIMEO on a
 *   blocking socket, write() returns EAGAIN after the timeout, but
 *   mbedTLS misclassifies it as MBEDTLS_ERR_NET_SEND_FAILED — a hard
 *   error that kills the HTTP/2 connection mid-transfer.  O_NONBLOCK
 *   makes mbedTLS return WANT_WRITE, which h2_send_callback translates
 *   to NGHTTP2_ERR_WOULDBLOCK.  The event loop then waits for POLLOUT.
 *
 * SO_RCVTIMEO = 200ms: prevents blocking the event loop on a partial
 *   TLS record.  h2_tls_receive() returns 0 on WANT_READ.
 *   Note: SO_RCVTIMEO has no effect when O_NONBLOCK is set (read()
 *   returns EAGAIN immediately), but we keep it as a safety net in
 *   case O_NONBLOCK is cleared elsewhere.
 */
static void h2_set_socket_timeouts(int fd) {
	struct timeval tv;
	int flags;

	/* Non-blocking writes: prevents mbedTLS EAGAIN misclassification */
	flags = fcntl(fd, F_GETFL);
	if (flags != -1) {
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	}

	/* Read timeout (safety net — O_NONBLOCK makes this a no-op) */
	tv.tv_sec = 0;
	tv.tv_usec = 200 * 1000;  /* 200ms */
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/* Forward declarations */
static void h2_mark_closing(t_http2_connection *conn);
static ssize_t h2_send_callback(nghttp2_session *ng_session, const uint8_t *data,
                                size_t length, int flags, void *user_data);
static int on_frame_recv_callback(nghttp2_session *ng_session, const nghttp2_frame *frame,
                                  void *user_data);
static int on_begin_headers_callback(nghttp2_session *ng_session, const nghttp2_frame *frame,
                                     void *user_data);
static int on_header_callback(nghttp2_session *ng_session, const nghttp2_frame *frame,
                              const uint8_t *name, size_t namelen,
                              const uint8_t *value, size_t valuelen,
                              uint8_t flags, void *user_data);
static int on_data_chunk_recv_callback(nghttp2_session *ng_session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data, size_t len,
                                       void *user_data);
static int on_stream_close_callback(nghttp2_session *ng_session, int32_t stream_id,
                                    uint32_t error_code, void *user_data);
static int on_frame_send_callback(nghttp2_session *ng_session, const nghttp2_frame *frame,
                                  void *user_data);

/* ========================================================================
 *  Shard state -- H2EventLoops shards, one thread each
 * ======================================================================== */

static t_h2_shard *h2_shards;
static int         h2_shard_count;

/* Which shard a new connection joins: round-robin, one atomic, no shard
 * state read.  The prediction is sharp -- c connections put floor(c/N) or
 * ceil(c/N) on every shard, exactly -- where least-connections would have to
 * read every shard's counters from a worker thread while the loop threads
 * write them.  It distributes ARRIVALS, not live connections; long-lived
 * connections landing unevenly stay uneven, and nothing here corrects that.
 *
 * Unsigned on purpose: signed overflow is undefined and would eventually
 * index the array with a negative number, while unsigned wrap is defined and
 * costs one uneven step per 2^32 connections. */
static volatile unsigned int h2_rr_next = 0;

/* Round robin, but never onto a loop that is no longer running: a shard
 * whose thread has left its while() still has everything an attach looks at
 * and nothing that will ever serve the connection.  NULL when no shard is
 * left; the caller refuses the connection, which closes it cleanly. */
static t_h2_shard *h2_shard_for_new_connection(void) {
	t_h2_shard *shard;
	unsigned int start, i;

	start = __sync_fetch_and_add(&h2_rr_next, 1);

	for (i = 0; i < (unsigned int)h2_shard_count; i++) {
		shard = &h2_shards[(start + i) % (unsigned int)h2_shard_count];

		if (__atomic_load_n(&(shard->running), __ATOMIC_SEQ_CST)) {
			return shard;
		}
	}

	return NULL;
}

/* Connection slots the PROCESS holds, against H2_MAX_CONNECTIONS.  The
 * ceiling is a property of the process and does not grow with the loop
 * count.  A sum over the shards' counters would read numbers other loop
 * threads are writing, so: one atomic, raised by the reserve-then-test in
 * h2_event_loop_add_connection(), lowered in h2_close_connection().  A
 * zombie holds no slot -- the release happens before the zombie transition,
 * exactly where the old conn_count-- gave the slot back. */
static volatile int h2_conn_slots_used = 0;

/* Active H2 worker count.  Incremented by h2_drain_dispatch_queue()
 * after successful start_worker(), decremented by h2_worker_process()
 * on every exit path.  Accessed from event loop + worker threads,
 * so we use GCC atomic builtins for thread safety.
 */
static volatile int h2_active_workers = 0;

/* ========================================================================
 *  Stream management
 * ======================================================================== */

static t_http2_stream *find_stream(t_http2_connection *conn, int32_t stream_id) {
	t_http2_stream *stream = conn->streams;

	while (stream != NULL) {
		if (stream->stream_id == stream_id) {
			return stream;
		}
		stream = stream->next;
	}

	return NULL;
}

static t_http2_stream *create_stream(t_http2_connection *conn, int32_t stream_id) {
	t_http2_stream *stream;

	if (conn->active_streams >= conn->base_session->binding->h2_max_concurrent_streams) {
		return NULL;
	}

	if ((stream = (t_http2_stream*)calloc(1, sizeof(t_http2_stream))) == NULL) {
		return NULL;
	}

	stream->stream_id = stream_id;
	stream->next = conn->streams;
	conn->streams = stream;
	conn->active_streams++;

	return stream;
}

static void free_h2_headers(t_http_header *headers) {
	t_http_header *next;

	while (headers != NULL) {
		next = headers->next;
		free(headers->data);
		headers->data = NULL;
		free(headers);
		headers = next;
	}
}

static void destroy_stream(t_http2_connection *conn, int32_t stream_id) {
	t_http2_stream *stream = conn->streams, *prev = NULL;

	while (stream != NULL) {
		if (stream->stream_id == stream_id) {
			if (prev == NULL) {
				conn->streams = stream->next;
			} else {
				prev->next = stream->next;
			}

			free(stream->method);
			stream->method = NULL;
			free(stream->path);
			stream->path = NULL;
			free(stream->authority);
			stream->authority = NULL;
			free(stream->scheme);
			stream->scheme = NULL;
			free(stream->body);
			stream->body = NULL;
			free_h2_headers(stream->headers);
			stream->headers = NULL;

			free(stream);
			conn->active_streams--;
			return;
		}

		prev = stream;
		stream = stream->next;
	}
}

static void destroy_all_streams(t_http2_connection *conn) {
	while (conn->streams != NULL) {
		destroy_stream(conn, conn->streams->stream_id);
	}
}

/* ========================================================================
 *  Header helpers
 * ======================================================================== */

static int add_stream_header(t_http2_stream *stream, const uint8_t *name, size_t namelen,
                             const uint8_t *value, size_t valuelen) {
	t_http_header *hdr;
	size_t datalen;

	if ((hdr = (t_http_header*)malloc(sizeof(t_http_header))) == NULL) {
		return -1;
	}

	if (namelen > SIZE_MAX - 3 - valuelen) {
		free(hdr);
		hdr = NULL;
		return -1;
	}
	datalen = namelen + 2 + valuelen;
	if ((hdr->data = (char*)malloc(datalen + 1)) == NULL) {
		free(hdr);
		hdr = NULL;
		return -1;
	}

	memcpy(hdr->data, name, namelen);
	hdr->data[namelen] = ':';
	hdr->data[namelen + 1] = ' ';
	memcpy(hdr->data + namelen + 2, value, valuelen);
	hdr->data[datalen] = '\0';

	hdr->length = (int)datalen;
	hdr->value_offset = (int)(namelen + 2);
	hdr->next = stream->headers;
	stream->headers = hdr;

	return 0;
}

static t_req_method parse_method(const char *method) {
	if (strcmp(method, "GET") == 0) return GET;
	if (strcmp(method, "QUERY") == 0) return QUERY;
	if (strcmp(method, "POST") == 0) return POST;
	if (strcmp(method, "HEAD") == 0) return HEAD;
	if (strcmp(method, "PUT") == 0) return PUT;
	if (strcmp(method, "DELETE") == 0) return DELETE;
	if (strcmp(method, "CONNECT") == 0) return CONNECT;
	if (strcmp(method, "TRACE") == 0) return TRACE;
	if (strcmp(method, "OPTIONS") == 0) return unsupported;
	if (strcmp(method, "PROPFIND") == 0) return unsupported;
	if (strcmp(method, "PROPPATCH") == 0) return unsupported;
	if (strcmp(method, "MKCOL") == 0) return unsupported;
	if (strcmp(method, "PATCH") == 0) return unsupported;
	return unknown;
}

/* ========================================================================
 *  Response data source for nghttp2
 * ======================================================================== */

static ssize_t h2_data_source_read(nghttp2_session *ng_session, int32_t stream_id,
                                    uint8_t *buf, size_t length, uint32_t *data_flags,
                                    nghttp2_data_source *source, void *user_data) {
	t_h2_data_source *src = (t_h2_data_source*)source->ptr;
	size_t remaining, to_copy;

	(void)user_data;

	remaining = src->length - src->offset;
	to_copy = remaining < length ? remaining : length;

	if (to_copy > 0) {
		memcpy(buf, src->data + src->offset, to_copy);
		src->offset += to_copy;
	}

	if (src->offset >= src->length) {
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
		/* Clear stream user data before freeing, so on_stream_close_callback
		 * does not double-free when the stream closes after EOF.
		 */
		nghttp2_session_set_stream_user_data(ng_session, stream_id, NULL);
		free(src->response_buf);
		src->response_buf = NULL;
		free(src);
		source->ptr = NULL;
	}

	return (ssize_t)to_copy;
}

/* ========================================================================
 *  Response submission (used by event loop after worker returns response)
 * ======================================================================== */

/* Submit a buffered HTTP/1.1 response to nghttp2.
 * The response_buf contains "HTTP/1.1 200 OK\r\nHeaders\r\n\r\nBody".
 * We parse it into structured headers and submit via nghttp2_submit_response().
 */
static int h2_submit_response_from_buf(t_http2_connection *conn, int32_t stream_id,
                                        char *response_buf, size_t response_size,
										bool truncated, t_req_method method,
                                        int return_code) {
	char *buf, *header_end, *line, *next_line, *colon, *space, *val_start;
	size_t header_len, body_offset, name_len, val_len, i;
	nghttp2_nv nv[H2_MAX_RESPONSE_HEADERS];
	int nv_count = 0;
	char status_str[4];
	nghttp2_data_provider data_prd;
	t_h2_data_source *data_src;
	const char *body_data;
	size_t body_len;
	char cl_str[24];
	long long content_length = -1;

	buf = response_buf;

	/* Handle empty response */
	if ((buf == NULL) || (response_size == 0)) {
		snprintf(status_str, sizeof(status_str), "%d", return_code);

		nv[0].name = (uint8_t*)":status";
		nv[0].namelen = 7;
		nv[0].value = (uint8_t*)status_str;
		nv[0].valuelen = strlen(status_str);
		nv[0].flags = NGHTTP2_NV_FLAG_NO_COPY_NAME;

		if (nghttp2_submit_headers(conn->ng_session, NGHTTP2_FLAG_END_STREAM,
		                           stream_id, NULL, nv, 1, NULL) != 0) {
			/* Couldn't queue the response headers (NOMEM, or the stream was
			 * already reset): RST the stream so the client is not left waiting
			 * for a response that will never arrive while we think it was
			 * answered. */
			nghttp2_submit_rst_stream(conn->ng_session, NGHTTP2_FLAG_NONE,
			                          stream_id, NGHTTP2_INTERNAL_ERROR);
			free(response_buf);
			response_buf = NULL;
			return -1;
		}
		free(response_buf);
		response_buf = NULL;
		return 0;
	}

	/* Find end of headers: "\r\n\r\n" */
	header_end = (char*)strnstr(buf, "\r\n\r\n", (int)response_size);
	if (header_end == NULL) {
		header_len = response_size;
		body_data = NULL;
		body_len = 0;
	} else {
		header_len = (size_t)(header_end - buf);
		body_offset = header_len + 4;
		body_data = buf + body_offset;
		body_len = response_size - body_offset;
	}

	/* Parse status from first line: "HTTP/1.1 200 OK\r\n" */
	line = buf;
	next_line = (char*)strnstr(line, "\r\n", (int)header_len);
	if (next_line == NULL) {
		snprintf(status_str, sizeof(status_str), "%d", return_code);
	} else {
		space = memchr(line, ' ', (size_t)(next_line - line));
		if ((space != NULL) && ((next_line - space) > 3)) {
			memcpy(status_str, space + 1, 3);
			status_str[3] = '\0';
		} else {
			snprintf(status_str, sizeof(status_str), "%d", return_code);
		}
		line = next_line + 2;
	}

	/* Add :status pseudo-header */
	nv[nv_count].name = (uint8_t*)":status";
	nv[nv_count].namelen = 7;
	nv[nv_count].value = (uint8_t*)status_str;
	nv[nv_count].valuelen = strlen(status_str);
	nv[nv_count].flags = NGHTTP2_NV_FLAG_NONE;
	nv_count++;

	/* Parse remaining header lines */
	while ((line < buf + header_len) && (nv_count < H2_MAX_RESPONSE_HEADERS)) {
		next_line = (char*)strnstr(line, "\r\n", (int)(buf + header_len - line));
		if (next_line == NULL) {
			next_line = buf + header_len;
		}

		if (next_line == line) {
			break;
		}

		colon = memchr(line, ':', (size_t)(next_line - line));
		if (colon == NULL) {
			line = next_line + 2;
			continue;
		}

		name_len = (size_t)(colon - line);
		val_start = colon + 1;

		while ((val_start < next_line) && (*val_start == ' ')) {
			val_start++;
		}
		val_len = (size_t)(next_line - val_start);

		/* The announced Content-Length, for the check below the loop: the
		 * body this buffer actually holds has to match it.  Copied out
		 * because response_buf is not NUL-terminated; a value too long for
		 * cl_str is a value no Content-Length has, and leaves the check off. */
		if ((name_len == 14) && (strncasecmp(line, "content-length", 14) == 0)) {
			if ((val_len > 0) && (val_len < sizeof(cl_str))) {
				memcpy(cl_str, val_start, val_len);
				cl_str[val_len] = '\0';
				content_length = strtoll(cl_str, NULL, 10);
				if (content_length < 0) {
					content_length = -1;
				}
			}
		}

		/* Skip HTTP/2 forbidden hop-by-hop headers (RFC 9113 Section 8.2.2) */
		if (((name_len == 10) && (strncasecmp(line, "connection", 10) == 0)) ||
		    ((name_len == 17) && (strncasecmp(line, "transfer-encoding", 17) == 0)) ||
		    ((name_len == 10) && (strncasecmp(line, "keep-alive", 10) == 0)) ||
		    ((name_len == 7)  && (strncasecmp(line, "upgrade", 7) == 0)) ||
		    ((name_len == 16) && (strncasecmp(line, "proxy-connection", 16) == 0))) {
			line = next_line + 2;
			continue;
		}

		/* RFC 9113 Section 8.2: header field names MUST be lowercase */
		for (i = 0; i < name_len; i++) {
			if ((line[i] >= 'A') && (line[i] <= 'Z')) {
				line[i] = line[i] + ('a' - 'A');
			}
		}

		nv[nv_count].name = (uint8_t*)line;
		nv[nv_count].namelen = name_len;
		nv[nv_count].value = (uint8_t*)val_start;
		nv[nv_count].valuelen = val_len;
		nv[nv_count].flags = NGHTTP2_NV_FLAG_NONE;
		nv_count++;

		line = next_line + 2;
	}

	/* Two different things make the buffer disagree with the Content-Length
	 * it carries, and they need opposite answers.
	 *
	 * 1. send.c gave up buffering (the response passed H2_MAX_RESPONSE_SIZE,
	 *    or an allocation failed) -- AFTER the headers were already in the
	 *    buffer.  The body is genuinely incomplete.  Submitting it would
	 *    announce a length the stream never delivers: the client got 200, a
	 *    truncated body, then a stream reset, and nothing logged -- and a
	 *    client that ignores the reset keeps a truncated file it was told
	 *    was complete.  Reset before the first body byte instead.  Decided
	 *    by the flag the worker set, not by comparing lengths: a truncated
	 *    response that announces no length at all is reset as well.
	 *
	 * 2. The buffer IS the whole response and the announced length is simply
	 *    wrong -- a CGI that says 100 and writes 5, or says 5 and writes 100.
	 *    Over HTTP/1.1 the announced value reaches the client as-is and the
	 *    client waits or cuts the body; over h2 the CLIENT's HTTP/2 library
	 *    rejects the DATA frame that carries END_STREAM before the announced
	 *    length (curl: "Violation in HTTP messaging rule", stream reset by
	 *    curl; a DATA frame beyond the length is its "Protocol error"), the
	 *    browser reports a connection failure, and no log says why.  The
	 *    buffer knows the real length, so that is what goes out: every
	 *    content-length header gets the byte count the DATA frames will
	 *    carry.  HEAD, 1xx, 204 and 304 are left alone -- they announce a
	 *    length without a body by design.
	 */
	if (truncated) {
		log_system(conn->shard->config, "HTTP/2 stream %d: response exceeded the HTTP/2 "
		           "buffer limit (%llu bytes buffered), resetting stream", (int)stream_id,
		           (unsigned long long)body_len);
		nghttp2_submit_rst_stream(conn->ng_session, NGHTTP2_FLAG_NONE,
		                          stream_id, NGHTTP2_INTERNAL_ERROR);
		check_free(response_buf);
		response_buf = NULL;
		return -1;
	}

	if ((content_length >= 0) && ((unsigned long long)content_length != (unsigned long long)body_len) &&
	    ((body_len > 0) || ((method != HEAD) && (empty_body_because_of_http_status(str_to_int(status_str)) == false)))) {
		log_system(conn->shard->config, "HTTP/2 stream %d: response announces Content-Length %lld "
		           "but holds %llu bytes, sending the actual length", (int)stream_id,
		           content_length, (unsigned long long)body_len);
		snprintf(cl_str, sizeof(cl_str), "%llu", (unsigned long long)body_len);
		for (i = 0; i < (size_t)nv_count; i++) {
			if ((nv[i].namelen == 14) && (memcmp(nv[i].name, "content-length", 14) == 0)) {
				nv[i].value = (uint8_t*)cl_str;
				nv[i].valuelen = strlen(cl_str);
			}
		}
	}

	/* Submit response with body data provider */
	if ((body_data != NULL) && (body_len > 0)) {
		if ((data_src = (t_h2_data_source*)malloc(sizeof(t_h2_data_source))) == NULL) {
			free(response_buf);
			response_buf = NULL;
			return -1;
		}
		data_src->data = body_data;
		data_src->length = body_len;
		data_src->offset = 0;
		data_src->response_buf = response_buf;  /* Transfer ownership */

		data_prd.source.ptr = data_src;
		data_prd.read_callback = h2_data_source_read;

		if (nghttp2_submit_response(conn->ng_session, stream_id,
		                             nv, (size_t)nv_count, &data_prd) != 0) {
			free(data_src->response_buf);
			data_src->response_buf = NULL;
			free(data_src);
			data_src = NULL;
			return -1;
		}
		/* Track data source so on_stream_close_callback can free it
		 * if the stream is reset before all data is read.
		 */
		nghttp2_session_set_stream_user_data(conn->ng_session, stream_id, data_src);
	} else {
		/* Headers-only response (e.g. HEAD) — submit first, then free buffer.
		 * nv entries point into response_buf, so it must stay alive until
		 * nghttp2_submit_response has copied the header data.
		 */
		if (nghttp2_submit_response(conn->ng_session, stream_id,
		                             nv, (size_t)nv_count, NULL) != 0) {
			free(response_buf);
			response_buf = NULL;
			return -1;
		}
		free(response_buf);
	}

	return 0;
}

/* ========================================================================
 *  Session initialization for worker (from work item, not from stream)
 * ======================================================================== */

static int h2_init_session_from_work_item(t_session *session, t_h2_work_item *item) {
	session->time = time(NULL);
	session->cgi_type = no_cgi;
	session->cgi_handler = NULL;
	session->fcgi_server = NULL;
	session->path_info = NULL;
	session->vars = NULL;
	session->extension = NULL;
	session->file_on_disk = NULL;
	session->mimetype = NULL;
	session->parsing_okay = true;
	session->keep_alive = false;
	session->header_sent = false;
	session->data_sent = false;
	session->uri_is_dir = false;
	session->encode_gzip = false;
	session->alias = NULL;
	session->script_alias = NULL;
	session->local_user = NULL;
	session->remote_user = NULL;
	session->http_auth = no_auth;
	session->directory = NULL;
	session->handling_error = false;
	session->reason_for_403 = "";
	session->cookies = NULL;
	session->bytes_sent = 0;
	session->output_size = 0;
	session->return_code = 200;
	session->error_cause = ec_NONE;
	session->error_code = -1;
	session->log_request = true;
	session->tempdata = NULL;
	session->uploaded_file = NULL;
	session->location = NULL;
	session->send_date = true;
	session->send_expires = false;
	session->expires = -1;
	session->caco_private = true;
	session->cause_of_30x = missing_slash;
	session->letsencrypt_auth_request = false;
	session->throttle = 0;
	session->bytecounter = 0;
	session->host = session->config->first_host;
	session->host_copied = false;
#ifdef ENABLE_TOOLKIT
	session->toolkit_fastcgi = NULL;
#endif

	/* Map work item fields to session */
	if ((item->method == NULL) || (item->path == NULL)) {
		return -1;
	}
	session->method = item->method;
	session->request_method = parse_method(item->method);

	if ((session->request_uri = strdup(item->path)) == NULL) {
		return -1;
	}

	if ((session->uri = strdup(item->path)) == NULL) {
		free(session->request_uri);
		session->request_uri = NULL;
		return -1;
	}

	if (register_tempdata(&(session->tempdata), session->uri, tc_data) == -1) {
		free(session->uri);
		session->uri = NULL;
		free(session->request_uri);
		session->request_uri = NULL;
		return -1;
	}

	session->uri_len = (int)strlen(item->path);
	if (item->authority != NULL) {
		char *hostname;

		if ((hostname = strdup(item->authority)) == NULL) {
			free(session->request_uri);
			session->request_uri = NULL;
			return -1;
		}

		if (register_tempdata(&(session->tempdata), hostname, tc_data) == -1) {
			free(hostname);
			free(session->request_uri);
			session->request_uri = NULL;
			return -1;
		}

		session->hostname = hostname;
	}
	session->http_version = "HTTP/2.0";
	session->header_length = 0;

	/* Borrow headers and body from work item */
	session->http_headers = item->headers;
	session->cookies = get_http_header("Cookie:", session->http_headers);
	session->body = item->body;
	session->content_length = (long)item->body_size;

	/* Count each HTTP/2 stream as a kept-alive request.
	 * Mirrors the kept_alive++ in parse_request() for HTTP/1.x.
	 */
	session->kept_alive++;

	/* HTTP/2 session state */
	session->is_http2 = true;
	session->h2_stream_id = item->stream_id;
	session->h2_connection = item->conn;
	session->h2_tls_version = item->tls_version;
	session->h2_tls_cipher = item->tls_cipher;
	session->h2_response_buf = NULL;
	session->h2_response_size = 0;
	session->h2_response_capacity = 0;
	session->h2_response_truncated = false;

	return 0;
}

/* Clean up per-request session fields after worker processing */
static void h2_cleanup_worker_session(t_session *session) {
	free(session->request_uri);
	session->request_uri = NULL;
	/* Do NOT free session->uri here — it is registered in tempdata
	 * (either the original strdup or a UrlToolkit rewrite) and will
	 * be freed by remove_tempdata() below.
	 */
	session->uri = NULL;
	/* Do NOT free session->hostname here — if it was strdup'd by
	 * remove_port_from_hostname(), it is registered in tempdata and
	 * will be freed by remove_tempdata() below.  Otherwise it points
	 * into the header buffer and must not be freed.
	 */
	session->hostname = NULL;
	free(session->file_on_disk);
	session->file_on_disk = NULL;
	free(session->path_info);
	session->path_info = NULL;
	free(session->location);
	session->location = NULL;

	/* Do NOT free h2_response_buf — it's transferred to the response item */

	if (session->uploaded_file != NULL) {
		unlink(session->uploaded_file);
		free(session->uploaded_file);
		session->uploaded_file = NULL;
	}

	/* Decrement directory client counter (mirrors reset_session in session.c) */
	if (session->directory != NULL) {
		pthread_mutex_lock(&(session->directory->client_mutex));
		if (session->part_of_dirspeed) {
			if (--session->directory->nr_of_clients == 0) {
				session->directory->session_speed = session->directory->upload_speed;
			} else {
				session->directory->session_speed = session->directory->upload_speed / session->directory->nr_of_clients;
			}
		}
		pthread_mutex_unlock(&(session->directory->client_mutex));
	}

	remove_tempdata(session->tempdata);
	session->tempdata = NULL;

#ifdef ENABLE_TOOLKIT
	/* Free per-request toolkit rules (mirrors reset_session in session.c) */
	if ((session->host_copied) && (session->host != NULL)) {
		if (session->host->toolkit_rules_user != NULL) {
			free(session->host->toolkit_rules_user);
		}
		remove_charlist(&(session->host->toolkit_rules_user_str));
	}
#endif

	if (session->host_copied) {
		free(session->host);
		session->host_copied = false;
	}
	session->host = NULL;

	check_free(session->request);
	session->request = NULL;
#ifdef CIFS
	check_free(session->extension);
	session->extension = NULL;
#endif

	check_clear_free(session->local_user, CHECK_USE_STRLEN);
	session->local_user = NULL;
	check_clear_free(session->remote_user, CHECK_USE_STRLEN);
	session->remote_user = NULL;

	/* Clear borrowed pointers */
	session->http_headers = NULL;
	session->body = NULL;
	session->method = NULL;
	session->http_version = NULL;
}

/* ========================================================================
 *  Deep-copy stream data into work item
 * ======================================================================== */

static t_http_header *clone_headers(t_http_header *src) {
	t_http_header *dst_head = NULL, *dst_tail = NULL, *copy;

	while (src != NULL) {
		if ((copy = (t_http_header*)malloc(sizeof(t_http_header))) == NULL) {
			free_h2_headers(dst_head);
			return NULL;
		}
		if ((copy->data = (char*)malloc((size_t)src->length + 1)) == NULL) {
			free(copy);
			copy = NULL;
			free_h2_headers(dst_head);
			return NULL;
		}
		memcpy(copy->data, src->data, (size_t)src->length + 1);
		copy->length = src->length;
		copy->value_offset = src->value_offset;
		copy->next = NULL;

		if (dst_tail == NULL) {
			dst_head = dst_tail = copy;
		} else {
			dst_tail->next = copy;
			dst_tail = copy;
		}
		src = src->next;
	}

	return dst_head;
}

static void free_work_item(t_h2_work_item *item) {
	if (item == NULL) {
		return;
	}

	check_free(item->method);
	item->method = NULL;

	check_free(item->path);
	item->path = NULL;

	check_free(item->authority);
	item->authority = NULL;

	check_free(item->body);
	item->body = NULL;

	free_h2_headers(item->headers);
	item->headers = NULL;

	/* Preallocated response never handed to the event loop (item flushed
	 * before dispatch, or clone failed mid-way).  The worker takes ownership
	 * by clearing this before filling it, so a non-NULL value here is unused. */
	if (item->response != NULL) {
		free(item->response->response_buf);
		free(item->response->log_uri);
		free(item->response);
		item->response = NULL;
	}

	free(item);
}

static t_h2_work_item *h2_clone_stream_to_work_item(t_http2_connection *conn,
                                                      t_http2_stream *stream) {
	t_h2_work_item *item;

	if ((item = (t_h2_work_item*)calloc(1, sizeof(t_h2_work_item))) == NULL) {
		return NULL;
	}

	/* Preallocate the response item so the worker's terminal path can never
	 * fail to return a response (a failure there would leak pending_requests
	 * and strand the connection as an un-freeable zombie).  If this fails the
	 * stream is RST'd before pending_requests is charged — no leak. */
	if ((item->response = (t_h2_response_item*)calloc(1, sizeof(t_h2_response_item))) == NULL) {
		free(item);
		return NULL;
	}
	item->response->conn = conn;
	item->response->shard = conn->shard;
	item->response->stream_id = stream->stream_id;

	item->conn = conn;
	item->stream_id = stream->stream_id;
	item->config = conn->base_session->config;
	item->binding = conn->base_session->binding;
	item->ip_address = conn->base_session->ip_address;
	item->remote_port = conn->base_session->remote_port;
	item->tls_version = tls_version_string(&(conn->base_session->tls_context));
	item->tls_cipher = tls_cipher_string(&(conn->base_session->tls_context));

	item->method = NULL;
	item->path = NULL;
	item->authority = NULL;
	item->headers = NULL;
	item->body = NULL;

	/* Deep-copy pseudo-headers */
	if (stream->method != NULL) {
		if ((item->method = strdup(stream->method)) == NULL) {
			goto fail;
		}
	}
	if (stream->path != NULL) {
		if ((item->path = strdup(stream->path)) == NULL) {
			goto fail;
		}
	}
	if (stream->authority != NULL) {
		if ((item->authority = strdup(stream->authority)) == NULL) {
			goto fail;
		}
	}

	/* Deep-copy headers */
	item->headers = clone_headers(stream->headers);
	if ((stream->headers != NULL) && (item->headers == NULL)) {
		goto fail;
	}

	/* Deep-copy body */
	if ((stream->body != NULL) && (stream->body_size > 0)) {
		if ((item->body = (char*)malloc(stream->body_size + 1)) == NULL) {
			goto fail;
		}
		memcpy(item->body, stream->body, stream->body_size);
		item->body[stream->body_size] = '\0';
		item->body_size = stream->body_size;
	}

	return item;

fail:
	free_work_item(item);

	return NULL;
}

/* Write in-memory PUT body to a temp file in upload_directory,
 * mirroring the store_on_disk path in fetch_request() for HTTP/1.1.
 * Returns 0 on success (session->uploaded_file is set), -1 on error.
 */
static int h2_write_put_tempfile(t_session *session, const char *body, size_t body_size) {
	int fd;

	if (session->config->upload_directory == NULL) {
		return -1;
	}

	if ((session->uploaded_file = (char*)malloc(session->config->upload_directory_len + 15)) == NULL) {
		return -1;
	}

	memcpy(session->uploaded_file, session->config->upload_directory, session->config->upload_directory_len);
	memcpy(session->uploaded_file + session->config->upload_directory_len, "/upload_XXXXXX", 15);

	if ((fd = mkstemp(session->uploaded_file)) == -1) {
		free(session->uploaded_file);
		session->uploaded_file = NULL;
		return -1;
	}

	if (body_size > 0) {
		if (write_buffer(fd, body, (long)body_size) == -1) {
			close(fd);
			unlink(session->uploaded_file);
			free(session->uploaded_file);
			session->uploaded_file = NULL;
			return -1;
		}
	}

	close(fd);

	return 0;
}

/* ========================================================================
 *  Worker-facing function: process a dispatched H2 request
 * ======================================================================== */

/* Hand a completed response to the event loop and wake it.  The response item
 * was preallocated on the work item, so this can never fail to allocate.
 * Called only from the worker thread. */
static void h2_push_response(t_h2_response_item *response) {
	t_h2_shard *shard = response->shard;

	response->next = NULL;

	pthread_mutex_lock(&shard->response_mutex);
	if (shard->response_tail != NULL) {
		shard->response_tail->next = response;
	} else {
		shard->response_head = response;
	}
	shard->response_tail = response;
	pthread_mutex_unlock(&shard->response_mutex);

	if (write(shard->wakeup_pipe[1], "R", 1) == -1) {
		/* Best effort — event loop picks it up on the next poll timeout */
	}
}

/* Did this stream open AFTER a challenge had already been answered on this
 * connection?  Then the client had the cookie and did not send it.
 *
 * The mark is the highest stream id the connection had received when a
 * challenge was answered (h2_challenge_answered), so every stream of the same
 * opening burst is at or below it.
 *
 * Strictly greater, and that matters: a browser opens its first streams in one
 * burst, and every one of them is answered with a challenge because none of
 * them could carry a cookie yet.  Only a stream opened after such an answer --
 * an id above the mark -- proves the client ignored it.
 */
bool h2_challenge_had_its_chance(t_session *session) {
	t_http2_connection *conn;
	int32_t answered;

	if ((conn = (t_http2_connection*)session->h2_connection) == NULL) {
		return false;
	}

	answered = __atomic_load_n(&(conn->challenge_stream_id), __ATOMIC_ACQUIRE);

	return (answered != 0) && (session->h2_stream_id > answered);
}

/* Record that a challenge went out, and mark EVERY stream this connection had
 * already received at that moment as having been in flight.
 *
 * The mark is conn->highest_stream_id, not the stream this worker is serving.
 * Publishing the own stream is racy in the one direction that costs a real
 * client its first visit: several workers answer the opening burst at once,
 * the one on the lowest stream may publish first, and a worker on a higher
 * stream of the SAME burst then reads a mark below itself and refuses.  Taking
 * the highest received id closes that: the event loop raised it for every
 * stream before any worker could run (on_begin_headers_callback), so no stream
 * of the burst is above the mark, and only a stream opened after the challenge
 * can be.
 *
 * Still a raise-only compare-exchange: two workers may answer at once and read
 * different snapshots of the highest id, and the mark must not fall back to
 * the older one.
 */
void h2_challenge_answered(t_session *session) {
	t_http2_connection *conn;
	int32_t answered, mark;

	if ((conn = (t_http2_connection*)session->h2_connection) == NULL) {
		return;
	}

	mark = __atomic_load_n(&(conn->highest_stream_id), __ATOMIC_ACQUIRE);
	if (mark < session->h2_stream_id) {
		/* Cannot normally happen: the loop records the id before the request
		 * is queued.  Never mark below the stream being answered. */
		mark = session->h2_stream_id;
	}

	answered = __atomic_load_n(&(conn->challenge_stream_id), __ATOMIC_ACQUIRE);
	while (mark > answered) {
		if (__atomic_compare_exchange_n(&(conn->challenge_stream_id), &answered,
		                                mark, true,
		                                __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
			break;
		}
	}
}

void h2_worker_process(t_h2_work_item *item) {
	t_session session;
	t_h2_response_item *response;
	int result;
	/* The owning shard, taken NOW: item and conn are gone by the time the
	 * counters below are settled (the response may already be consumed and
	 * the connection freed), while the shard array lives until process end. */
	t_h2_shard *shard = item->conn->shard;

	/* Initialize a stack-allocated session for request processing */
	memset(&session, 0, sizeof(session));
	session.config = item->config;
	session.binding = item->binding;
	session.ip_address = item->ip_address;
	session.remote_port = item->remote_port;
	session.client_socket = -1;  /* Worker must NEVER touch the socket */
	session.socket_open = true;  /* Logical — response buffering needs this */
	session.request_limit = true;
	__atomic_store_n(&(session.force_quit), false, __ATOMIC_RELEASE);
	session.last_host = NULL;
	session.request = NULL;
	session.buffer_size = 0;
	session.bytes_in_buffer = 0;
#ifdef ENABLE_RPROXY
	session.rproxy_kept_alive = false;
#endif

	/* Validate required pseudo-headers */
	if ((item->method == NULL) || (item->path == NULL)) {
		/* Queue a 400 response (preallocated — see h2_clone_stream_to_work_item) */
		response = item->response;
		item->response = NULL;
		response->return_code = 400;
		response->log_request = false;
		h2_push_response(response);
		free_work_item(item);
		goto done;
	}

	/* HTTP/2 PUT handling: the body arrives via DATA frames and is buffered in
	 * memory by on_data_chunk_recv (bounded there by max_request_size; an
	 * over-limit body is RST'd before it reaches this worker).  Disk-
	 * buffering in the nghttp2 callback is deliberately avoided: callbacks run on
	 * the single event-loop thread and blocking I/O there would stall every
	 * connection.  The buffered body is written to a temp file below, mirroring
	 * fetch_request() for HTTP/1.1; session->uploaded_file is set before
	 * handle_request() so handle_put_request() in target.c works unchanged.
	 *
	 * max_upload_size is a DISTINCT limit from max_request_size, and the config
	 * does NOT cross-validate them — either may be larger (serverconfig.c). A PUT
	 * body must satisfy BOTH: max_request_size is enforced in on_data_chunk_recv;
	 * max_upload_size is enforced here with a 413, mirroring the HTTP/1.1
	 * store_on_disk path (http.c) and matching its status.  This gate reads only
	 * worker-owned fields (item->binding config + item->body_size) and pushes the
	 * preallocated response, so it touches no event-loop state and is race-free.
	 * Do NOT drop it assuming max_request_size is always the tighter cap:
	 * when max_request_size > max_upload_size it is the sole max_upload_size
	 * enforcement on the HTTP/2 path (handle_put_request does not re-check). */
	if ((item->method != NULL) && (strcmp(item->method, "PUT") == 0) &&
	    (item->binding->max_upload_size > 0) &&
	    ((long)item->body_size > item->binding->max_upload_size)) {
		response = item->response;
		item->response = NULL;
		response->return_code = 413;
		response->log_request = false;
		h2_push_response(response);
		free_work_item(item);
		goto done;
	}

	if (h2_init_session_from_work_item(&session, item) != 0) {
		/* OOM during session init — queue 500 response */
		response = item->response;
		item->response = NULL;
		response->return_code = 500;
		response->log_request = false;
		h2_push_response(response);
		h2_cleanup_worker_session(&session);
		free_work_item(item);
		goto done;
	}

	/* Write PUT body to temp file so handle_put_request() finds it */
	if ((item->method != NULL) && (strcmp(item->method, "PUT") == 0)) {
		if (h2_write_put_tempfile(&session, item->body, item->body_size) == -1) {
			log_error_session(&session, "can't create temporary file for PUT request");
			response = item->response;
			item->response = NULL;
			response->return_code = 500;
			response->log_request = false;
			h2_push_response(response);
			h2_cleanup_worker_session(&session);
			free_work_item(item);
			goto done;
		}
	}

	/* Process the request through the standard Hiawatha pipeline */
#ifdef ENABLE_DEBUG
	session.current_task = "fetch & parse HTTP/2 request";
#endif
	result = handle_request(&session);
	handle_request_result(&session, result);

#ifdef ENABLE_MONITOR
	if (session.config->monitor_enabled) {
		monitor_count_host(&session);
	}
#endif

	/* Flush buffered output into h2_response_buf */
	send_buffer(&session, NULL, 0);

	/* Return the response via the preallocated item — no allocation here can
	 * fail, so a dispatched request ALWAYS produces exactly one response and
	 * the event loop always decrements pending_requests / inflight_workers. */
	response = item->response;
	item->response = NULL;
	response->response_buf = session.h2_response_buf;
	response->response_size = session.h2_response_size;
	response->response_truncated = session.h2_response_truncated;
	response->return_code = session.return_code;
	response->log_request = session.log_request;
	response->bytes_sent = session.bytes_sent;
	response->request_method = session.request_method;
	/* Hand any per-directory throttle back to the event loop instead of writing
	 * conn->base_session->throttle from this worker thread: the event loop
	 * reads that field (and bytecounter/throttle_timer) in h2_send_callback, so a
	 * worker-side write races it.  process_response_queue applies it. */
	response->throttle = session.throttle;
	if (session.request_uri != NULL) {
		response->log_uri = strdup(session.request_uri);
		if (response->log_uri == NULL) {
			response->log_request = false;
		}
	}

	/* Detach response_buf from session — ownership transfers to response item */
	session.h2_response_buf = NULL;
	session.h2_response_size = 0;
	session.h2_response_capacity = 0;

	h2_push_response(response);

	/* Cleanup */
	h2_cleanup_worker_session(&session);
	free_work_item(item);

done:
	__sync_fetch_and_sub(&(shard->active_workers), 1);
	__sync_fetch_and_sub(&h2_active_workers, 1);
}

/* ========================================================================
 *  Dispatch to worker thread pool
 * ======================================================================== */

static int h2_dispatch_to_worker(t_h2_work_item *item) {
	t_session *wrapper;

	/* Allocate a lightweight wrapper session for start_worker() */
	if ((wrapper = (t_session*)malloc(sizeof(t_session))) == NULL) {
		return -1;
	}

	/* Minimal init — only what start_worker/connection_handler needs */
	memset(wrapper, 0, sizeof(t_session));
	wrapper->config = item->config;
	wrapper->binding = item->binding;
	wrapper->ip_address = item->ip_address;
	wrapper->client_socket = -1;
	wrapper->is_h2_work = true;
	wrapper->h2_work_item = item;

	if (start_worker(wrapper) != 0) {
		free(wrapper);
		wrapper = NULL;
		return -1;
	}

	return 0;
}

/* ========================================================================
 *  Bounded dispatch queue
 *
 *  Problem: on_frame_recv_callback() fires for every completed stream
 *  in a single nghttp2_session_recv() pass.  With 100 connections × 32
 *  concurrent streams, all 3200 requests can arrive in one poll cycle.
 *  Direct dispatch via start_worker() → pthread_create() fails when the
 *  OS thread limit is exceeded → RST_STREAM(INTERNAL_ERROR).
 *
 *  Solution: enqueue completed requests per connection, drain greedily
 *  from the event loop.  start_worker() failure stops the drain; items
 *  remain queued and are retried in the next cycle.
 *
 *  Thread safety: only the event loop thread touches these queues.
 *  Workers interact solely via the response queue (response_mutex).
 * ======================================================================== */

/* Enqueue a completed request for deferred worker dispatch.
 * Called from on_frame_recv_callback() when END_STREAM is received.
 * Returns -1 if queue is full (caller must RST_STREAM the stream).
 * pending_requests is incremented here, not at dispatch time, so that
 * shutdown drain and zombie lifecycle correctly track queued items.
 */
static int h2_enqueue_request(t_http2_connection *conn, t_h2_work_item *item) {
	if (conn->queued_count >= H2_MAX_QUEUED_PER_CONN) {
		return -1;
	}

	item->next = NULL;
	if (conn->queue_tail != NULL) {
		conn->queue_tail->next = item;
	} else {
		conn->queue_head = item;
	}
	conn->queue_tail = item;
	conn->queued_count++;
	conn->pending_requests++;
	conn->requests_served++;

	return 0;
}

/* Free all queued items without dispatching them.  Decrements
 * pending_requests for each item.  Called from:
 * - h2_close_connection(): queued items were never sent to workers
 * - h2_event_loop_shutdown(): event loop stopped, no workers will pick up
 */
static void h2_flush_queue(t_http2_connection *conn) {
	t_h2_work_item *item = conn->queue_head;
	t_h2_work_item *next;

	while (item != NULL) {
		next = item->next;
		conn->pending_requests--;
		free_work_item(item);
		item = next;
	}
	conn->queue_head = NULL;
	conn->queue_tail = NULL;
	conn->queued_count = 0;
}

/* Dispatch queued items to worker threads.  Respects H2_MAX_WORKERS
 * to prevent pthread_create() exhaustion under burst load.
 *
 * Called at 3 points per event loop iteration:
 * 1. After process_response_queue() — workers finished, slots free
 * 2. After connection I/O — new items were just enqueued by callbacks
 * 3. During graceful shutdown drain — flush remaining work
 *
 * On start_worker() failure: break (not return) so other connections
 * still get a chance.  Worker limit hit: return early, next drain
 * cycle will pick up when workers finish and decrement the counter.
 */
static void h2_drain_dispatch_queue(t_h2_shard *shard) {
	t_http2_connection *conn;
	t_h2_work_item *item, *next_item;
	int i, conn_cap;

	for (i = 0; i < shard->conn_count; i++) {
		conn = shard->connections[i];

		/* Per-connection in-flight cap = the negotiated concurrent-stream
		 * limit.  RST_STREAM frees the nghttp2 stream slot immediately but
		 * NOT the worker already dispatched for that stream, so without this
		 * cap a rapid-reset flood on one connection could dispatch unbounded
		 * workers and monopolise the global pool (app-layer CVE-2023-44487).
		 * A well-behaved client never exceeds its own stream concurrency;
		 * excess simply stays queued and dispatches as workers finish. */
		conn_cap = conn->base_session->binding->h2_max_concurrent_streams;
		if (conn_cap <= 0) {
			conn_cap = H2_MAX_CONCURRENT_STREAMS;
		}

		while (conn->queue_head != NULL) {
			/* Backpressure: don't exceed the global worker limit */
			if (__sync_fetch_and_add(&h2_active_workers, 0) >= H2_MAX_WORKERS) {
				return;  /* at capacity — retry when workers finish */
			}

			/* Fairness: don't let one connection exceed its share */
			if (conn->inflight_workers >= conn_cap) {
				break;  /* serve the other connections; retry next cycle */
			}

			item = conn->queue_head;
			next_item = item->next;
			__sync_fetch_and_add(&h2_active_workers, 1);
			__sync_fetch_and_add(&(shard->active_workers), 1);
			if (h2_dispatch_to_worker(item) != 0) {
				__sync_fetch_and_sub(&(shard->active_workers), 1);
				__sync_fetch_and_sub(&h2_active_workers, 1);
				break;  /* this connection's dispatch failed — try others */
			}
			conn->inflight_workers++;

			conn->queue_head = next_item;
			if (conn->queue_head == NULL) {
				conn->queue_tail = NULL;
			}
			conn->queued_count--;
		}
	}
}

/* ========================================================================
 *  nghttp2 callbacks
 * ======================================================================== */

static int on_begin_headers_callback(nghttp2_session *ng_session, const nghttp2_frame *frame,
                                     void *user_data) {
	t_http2_connection *conn = (t_http2_connection*)user_data;

	(void)ng_session;

	if ((frame->hd.type != NGHTTP2_HEADERS) || (frame->headers.cat != NGHTTP2_HCAT_REQUEST)) {
		return 0;
	}

	/* Don't accept new streams on a closing connection */
	if (conn->closing) {
		return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
	}

	if (create_stream(conn, frame->hd.stream_id) == NULL) {
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	/* ChallengeClient (http2.h): the mark a worker publishes is this value,
	 * not the stream that worker is serving.  Recorded here, in the event
	 * loop thread, BEFORE the request can reach a worker -- so every stream a
	 * worker may run has already raised it.  Only ever grows; nghttp2 refuses
	 * a stream id below the last one, so the test is a guard, not a race. */
	if (frame->hd.stream_id > __atomic_load_n(&(conn->highest_stream_id), __ATOMIC_RELAXED)) {
		__atomic_store_n(&(conn->highest_stream_id), frame->hd.stream_id, __ATOMIC_RELEASE);
	}

	return 0;
}

static int on_header_callback(nghttp2_session *ng_session, const nghttp2_frame *frame,
                              const uint8_t *name, size_t namelen,
                              const uint8_t *value, size_t valuelen,
                              uint8_t flags, void *user_data) {
	t_http2_connection *conn = (t_http2_connection*)user_data;
	t_http2_stream *stream;
	size_t old_len, new_len;
	char *new_data;

	(void)ng_session;
	(void)flags;

	if ((frame->hd.type != NGHTTP2_HEADERS) || (frame->headers.cat != NGHTTP2_HCAT_REQUEST)) {
		return 0;
	}

	if ((namelen > H2_MAX_HEADER_VALUE_LEN) || (valuelen > H2_MAX_HEADER_VALUE_LEN)) {
		return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
	}

	if ((stream = find_stream(conn, frame->hd.stream_id)) == NULL) {
		return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
	}

	/* Enforce total header list size limit */
	stream->header_list_size += namelen + valuelen + 32;
	if (stream->header_list_size > H2_MAX_HEADER_LIST_SIZE) {
		return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
	}

	if ((namelen > 0) && (name[0] == ':')) {
		if ((namelen == 7) && (memcmp(name, ":method", 7) == 0)) {
			free(stream->method);
			if ((stream->method = strndup((const char*)value, valuelen)) == NULL) {
				return NGHTTP2_ERR_CALLBACK_FAILURE;
			}
		} else if ((namelen == 5) && (memcmp(name, ":path", 5) == 0)) {
			/* Enforce max_url_length (mirrors parse_request() → 414) */
			if ((conn->base_session->config->max_url_length > 0) &&
			    ((int)valuelen > conn->base_session->config->max_url_length)) {
				return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
			}
			free(stream->path);
			if ((stream->path = strndup((const char*)value, valuelen)) == NULL) {
				return NGHTTP2_ERR_CALLBACK_FAILURE;
			}
		} else if ((namelen == 10) && (memcmp(name, ":authority", 10) == 0)) {
			free(stream->authority);
			if ((stream->authority = strndup((const char*)value, valuelen)) == NULL) {
				return NGHTTP2_ERR_CALLBACK_FAILURE;
			}
		} else if ((namelen == 7) && (memcmp(name, ":scheme", 7) == 0)) {
			free(stream->scheme);
			if ((stream->scheme = strndup((const char*)value, valuelen)) == NULL) {
				return NGHTTP2_ERR_CALLBACK_FAILURE;
			}
		}
	} else {
		/* RFC 7540 §8.1.2.5: concatenate multiple cookie headers with "; " */
		if ((namelen == 6) && (memcmp(name, "cookie", 6) == 0)) {
			t_http_header *hdr = stream->headers;

			while (hdr != NULL) {
				if (strncasecmp(hdr->data, "cookie:", 7) == 0) {
					old_len = (size_t)hdr->length;
					new_len = old_len + 2 + valuelen;

					if ((new_data = (char*)realloc(hdr->data, new_len + 1)) == NULL) {
						return NGHTTP2_ERR_CALLBACK_FAILURE;
					}

					new_data[old_len] = ';';
					new_data[old_len + 1] = ' ';
					memcpy(new_data + old_len + 2, value, valuelen);
					new_data[new_len] = '\0';
					hdr->data = new_data;
					hdr->length = (int)new_len;

					return 0;
				}

				hdr = hdr->next;
			}
		}

		if (add_stream_header(stream, name, namelen, value, valuelen) == -1) {
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}

	return 0;
}

static int on_data_chunk_recv_callback(nghttp2_session *ng_session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data, size_t len,
                                       void *user_data) {
	t_http2_connection *conn = (t_http2_connection*)user_data;
	t_http2_stream *stream;
	size_t new_capacity;
	char *new_body;

	(void)ng_session;
	(void)flags;

	if ((stream = find_stream(conn, stream_id)) == NULL) {
		return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
	}

	/* Already over the limit: the stream was RST'd on the chunk that first
	 * exceeded it.  Keep discarding further chunks without regrowing the buffer
	 * or re-submitting RST until nghttp2 closes the stream. */
	if (stream->body_too_large) {
		return 0;
	}

	/* Enforce max_request_size: header block + in-memory body combined
	 * (mirrors fetch_request() for HTTP/1.x).  IMPORTANT: nghttp2 SILENTLY
	 * IGNORES a non-fatal error return from this callback (verified against
	 * 1.69.0: nghttp2_session_mem_recv only escalates nghttp2_is_fatal codes,
	 * < -900; TEMPORAL_CALLBACK_FAILURE is -521).  Returning an error here would
	 * therefore just drop this chunk and let a SILENTLY TRUNCATED body reach the
	 * worker.  Instead flag the stream and RST it cleanly, so on_frame_recv does
	 * not dispatch a worker for a torso request. */
	if (conn->base_session->binding->max_request_size > 0) {
		if (stream->header_list_size + stream->body_size + len >
		    (size_t)conn->base_session->binding->max_request_size) {
			stream->body_too_large = true;
			nghttp2_submit_rst_stream(conn->ng_session, NGHTTP2_FLAG_NONE,
			                          stream_id, NGHTTP2_ENHANCE_YOUR_CALM);
			return 0;
		}
	}

	if (stream->body_size + len >= stream->body_capacity) {
		new_capacity = stream->body_capacity == 0 ? 4096 : stream->body_capacity;
		while (new_capacity < stream->body_size + len + 1) {
			if (new_capacity > SIZE_MAX / 2) {
				return NGHTTP2_ERR_CALLBACK_FAILURE;
			}
			new_capacity *= 2;
		}
		if ((new_body = (char*)realloc(stream->body, new_capacity)) == NULL) {
			return NGHTTP2_ERR_CALLBACK_FAILURE;
		}
		stream->body = new_body;
		stream->body_capacity = new_capacity;
	}

	memcpy(stream->body + stream->body_size, data, len);
	stream->body_size += len;

	return 0;
}

/* Frame received: enqueue completed requests for worker dispatch.
 * Previously dispatched directly via h2_dispatch_to_worker(), which
 * caused thread exhaustion under burst load.  Now enqueues; the event
 * loop drains via h2_drain_dispatch_queue().
 */
static int on_frame_recv_callback(nghttp2_session *ng_session, const nghttp2_frame *frame,
                                  void *user_data) {
	t_http2_connection *conn = (t_http2_connection*)user_data;
	t_http2_stream *stream;
	t_h2_work_item *item;

	(void)ng_session;

	switch (frame->hd.type) {
		case NGHTTP2_HEADERS:
			if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
				break;
			}

			if ((stream = find_stream(conn, frame->hd.stream_id)) == NULL) {
				break;
			}

			stream->headers_complete = true;

			if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
				stream->request_complete = true;
				item = h2_clone_stream_to_work_item(conn, stream);
				if (item == NULL) {
					nghttp2_submit_rst_stream(conn->ng_session, NGHTTP2_FLAG_NONE,
					                          frame->hd.stream_id, NGHTTP2_INTERNAL_ERROR);
				} else if (h2_enqueue_request(conn, item) != 0) {
					/* queue full — backpressure */
					free_work_item(item);
					nghttp2_submit_rst_stream(conn->ng_session, NGHTTP2_FLAG_NONE,
					                          frame->hd.stream_id, NGHTTP2_INTERNAL_ERROR);
				}
			}
			break;

		case NGHTTP2_DATA:
			if ((stream = find_stream(conn, frame->hd.stream_id)) == NULL) {
				break;
			}

			/* Body exceeded max_request_size: the stream was already RST'd in
			 * on_data_chunk_recv — don't dispatch a worker for a torso request. */
			if (stream->body_too_large) {
				break;
			}

			if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
				stream->request_complete = true;
				item = h2_clone_stream_to_work_item(conn, stream);
				if (item == NULL) {
					nghttp2_submit_rst_stream(conn->ng_session, NGHTTP2_FLAG_NONE,
					                          frame->hd.stream_id, NGHTTP2_INTERNAL_ERROR);
				} else if (h2_enqueue_request(conn, item) != 0) {
					/* queue full — backpressure */
					free_work_item(item);
					nghttp2_submit_rst_stream(conn->ng_session, NGHTTP2_FLAG_NONE,
					                          frame->hd.stream_id, NGHTTP2_INTERNAL_ERROR);
				}
			}
			break;

		case NGHTTP2_GOAWAY:
			/* Client sent GOAWAY — no new streams will arrive.
			 * Mark closing so we drain pending responses and clean up,
			 * instead of holding the connection for H2_IDLE_TIMEOUT.
			 */
			h2_mark_closing(conn);
			break;

		default:
			break;
	}

	/* H2MaxRequests: initiate graceful close after serving the configured
	 * maximum number of requests on this connection.  Frees per-connection
	 * memory allocations.  Pending responses are drained before close.
	 */
	if ((conn->base_session->binding->h2_max_requests > 0) &&
	    (conn->requests_served >= conn->base_session->binding->h2_max_requests)) {
		h2_mark_closing(conn);
	}

	return 0;
}

static int on_stream_close_callback(nghttp2_session *ng_session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
	t_http2_connection *conn = (t_http2_connection*)user_data;
	t_h2_data_source *data_src;

	(void)error_code;

	/* Free leaked data source if stream was reset before response was
	 * fully sent.  In the normal case (EOF reached), h2_data_source_read
	 * already cleared this to NULL.
	 */
	data_src = (t_h2_data_source*)nghttp2_session_get_stream_user_data(ng_session, stream_id);
	if (data_src != NULL) {
		free(data_src->response_buf);
		data_src->response_buf = NULL;
		free(data_src);
		nghttp2_session_set_stream_user_data(ng_session, stream_id, NULL);
	}

	destroy_stream(conn, stream_id);

	return 0;
}

/* BanOnGarbage's HTTP/2 half.  On HTTP/1.1 a malformed request line is
 * answered 400 and banned at once (workers.c, case 400).  HTTP/2 has no
 * request line: a malformed frame or header block is a CONNECTION error,
 * which nghttp2 answers itself before any request exists -- so it never
 * reaches the 400 branch, and BanOnGarbage protected h1.1 while silently
 * doing nothing on h2 for the same client behaviour (SEC-026).
 *
 * Why here and not where the connection is torn down.  Three tempting
 * places are all wrong:
 *
 *   h2_mark_closing() has ELEVEN call sites in this tree and is the general
 *   "this connection is going away" marker.  One of them is the graceful
 *   drain at shutdown -- a ban there would ban every connected client when
 *   the server stops.
 *
 *   A negative return from nghttp2_session_mem_recv() is NOT the
 *   protocol-error path: it escalates only nghttp2_is_fatal codes
 *   (NOMEM, CALLBACK_FAILURE).  That is our failure, not the client's;
 *   banning there bans a client because we ran out of memory.
 *
 *   want_read() == 0 && want_write() == 0 means "the session is finished",
 *   which a polite client GOAWAY reaches just as surely as a broken one.
 *
 * The one signal that means "the client got the protocol wrong" is a
 * GOAWAY WE send with an error code other than NO_ERROR.  Our own
 * goodbyes -- connection teardown and the drain -- pass NO_ERROR
 * explicitly, so they cannot be confused with it.
 *
 * Measured for the big 12.4 before this was written (2026-08-13, nghttp2
 * 1.64), because it is library behaviour and not ours: a SETTINGS frame of
 * length 3 (not a multiple of 6, RFC 9113 6.5) produced GOAWAY error_code=6
 * through this callback, while a polite client GOAWAY, an ordinary request
 * and the server's own shutdown drain each produced error_code=0.
 *
 * Booked once per connection: a connection error ends the connection, so
 * unlike the per-request h1.1 count there is nothing here that could
 * multiply -- but the teardown path may still send a second GOAWAY, and
 * one mistake must not be charged twice.
 *
 * The message deliberately repeats h1.1's wording, so one grep over the
 * system log finds both protocols' bans; the detail is appended, not
 * substituted.  monitor_count_bad_request() is NOT called: no request was
 * ever parsed, so there is no bad request to count -- only the ban.
 */
static int on_frame_send_callback(nghttp2_session *ng_session, const nghttp2_frame *frame,
                                  void *user_data) {
	t_http2_connection *conn = (t_http2_connection*)user_data;
	t_session *session;

	(void)ng_session;

	if ((frame->hd.type == NGHTTP2_GOAWAY) &&
	    (frame->goaway.error_code != NGHTTP2_NO_ERROR) &&
	    (conn->goaway_booked == false)) {
		session = conn->base_session;

		conn->goaway_booked = true;

		if ((session->config->ban_on_garbage > 0) &&
		    (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
			ban_ip(&(session->ip_address), session->config->ban_on_garbage, session->config->kick_on_ban);
			log_system_session(session, "Client banned because of sending garbage (HTTP/2 protocol error, GOAWAY %u)",
			                   (unsigned)frame->goaway.error_code);
#ifdef ENABLE_MONITOR
			if (session->config->monitor_enabled) {
				monitor_count_ban(session);
			}
#endif
		}
	}

	return 0;
}

/* nghttp2 I/O: send data to TLS socket (non-blocking).
 *
 * Calls mbedtls_ssl_write() directly (no retry loop). On WANT_WRITE
 * (socket send buffer full), returns NGHTTP2_ERR_WOULDBLOCK so nghttp2
 * pauses and the event loop waits for POLLOUT before retrying.
 *
 * mbedtls guarantees: after WANT_WRITE, the next call MUST use the
 * exact same buffer pointer and length. nghttp2 guarantees: after
 * WOULDBLOCK, send_callback is called with the same data/length.
 * These guarantees align, making non-blocking writes safe.
 */
static ssize_t h2_send_callback(nghttp2_session *ng_session, const uint8_t *data,
                                size_t length, int flags, void *user_data) {
	t_http2_connection *conn = (t_http2_connection*)user_data;
	int result;
	time_t new_time;

	(void)ng_session;
	(void)flags;

	/* Throttle: limit send rate per connection, matching HTTP/1.1 logic
	 * in send_to_client(). Instead of usleep() (which would block the
	 * event loop), return WOULDBLOCK so nghttp2 retries on the next
	 * poll cycle.
	 */
	if (conn->base_session->throttle > 0) {
		new_time = time(NULL);
		if (conn->base_session->throttle_timer < new_time) {
			conn->base_session->bytecounter = 0;
			conn->base_session->throttle_timer = new_time;
		}
		if (conn->base_session->bytecounter >= conn->base_session->throttle) {
			/* Timer throttle, NOT socket back-pressure: the socket is writable,
			 * so do NOT set write_blocked / request HP_OUT — that spun the
			 * event loop at 100% CPU (writability fires immediately on a
			 * writable socket).  Defer this connection's writes to the next
			 * 1-second window; h2_conn_refresh_interest() withholds HP_OUT
			 * until throttle_until has passed.  The 1000 ms tick is what
			 * re-examines the field, on every backend. */
			conn->throttle_until = conn->base_session->throttle_timer + 1;
			return NGHTTP2_ERR_WOULDBLOCK;
		}
	}

	result = mbedtls_ssl_write(&(conn->base_session->tls_context),
	                           (const unsigned char*)data, length);

	if ((result == MBEDTLS_ERR_SSL_WANT_WRITE) ||
	    (result == MBEDTLS_ERR_SSL_WANT_READ)) {
		conn->write_blocked = true;
		return NGHTTP2_ERR_WOULDBLOCK;
	}

	/* Safety net: catch EAGAIN that mbedTLS may misclassify as a hard
	 * error (MBEDTLS_ERR_NET_SEND_FAILED) if the socket reverts to
	 * blocking mode or SO_SNDTIMEO is set elsewhere.
	 */
	if ((result < 0) && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		conn->write_blocked = true;
		return NGHTTP2_ERR_WOULDBLOCK;
	}

	if (result < 0) {
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}

	/* Throttle accounting after successful write */
	conn->base_session->bytecounter += result;

	conn->write_blocked = false;
	return (ssize_t)result;
}

/* ========================================================================
 *  Connection initialization (called from event loop add)
 * ======================================================================== */

static int h2_init_connection(t_http2_connection *conn) {
	nghttp2_session_callbacks *callbacks = NULL;
	nghttp2_settings_entry settings[2];

	if (nghttp2_session_callbacks_new(&callbacks) != 0) {
		return -1;
	}

	nghttp2_session_callbacks_set_send_callback(callbacks, h2_send_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
	nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);

	if (nghttp2_session_server_new(&conn->ng_session, callbacks, conn) != 0) {
		nghttp2_session_callbacks_del(callbacks);
		return -1;
	}
	nghttp2_session_callbacks_del(callbacks);

	settings[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
	settings[0].value = (uint32_t)conn->base_session->binding->h2_max_concurrent_streams;
	settings[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
	settings[1].value = 65535;

	if (nghttp2_submit_settings(conn->ng_session, NGHTTP2_FLAG_NONE, settings, 2) != 0) {
		nghttp2_session_del(conn->ng_session);
		return -1;
	}

	/* Don't send SETTINGS here — the worker thread shouldn't use
	 * the TLS context after handing off to the event loop.
	 * The event loop will send SETTINGS on the first poll cycle
	 * via process_response_queue()'s flush loop (which calls
	 * nghttp2_session_send for all connections with pending data).
	 */

	return 0;
}

/* ========================================================================
 *  Connection close and cleanup
 * ======================================================================== */

/* Mark connection as closing.  The per-IP client slot is NOT released here:
 * a closing connection keeps its socket, TLS context and session alive until
 * pending worker responses drain (up to H2_CLOSING_TIMEOUT), so it must keep
 * counting against connections_per_ip for its real lifetime.  Releasing the
 * slot early let a single IP cycle connections into the closing state and open
 * fresh ones without bound, defeating the per-IP limit.  h2_free_connection()
 * releases the slot once the connection is actually torn down.
 */
static void h2_mark_closing(t_http2_connection *conn) {
	if (conn->closing) {
		return;
	}

	conn->closing = true;
	conn->closing_since = time(NULL);
}

/* Close and free a connection.  Must only be called when
 * pending_requests == 0 (all worker responses have been drained).
 */
static void h2_free_connection(t_http2_connection *conn) {
	/* Release per-IP slot if not already done by h2_mark_closing */
	if (!conn->client_removed) {
		if (conn->base_session->config->reconnect_delay > 0) {
			mark_client_for_removal(conn->base_session,
			                        conn->base_session->config->reconnect_delay);
		} else {
			remove_client(conn->base_session);
		}
	}

	free(conn->base_session);
	conn->base_session = NULL;
	free(conn);
}

/* Close the socket/TLS and release nghttp2 state, but do NOT free(conn)
 * if workers still have outstanding responses.  In that case the
 * connection is moved to the zombie list and freed later.
 */
static void h2_close_connection(t_http2_connection *conn) {
	t_h2_shard *shard = conn->shard;
	t_http2_connection **new_arr;
	int new_cap;

	/* Out of the poller first: close_socket() below frees the descriptor
	 * number, the kernel hands the same number to the next accept, and a
	 * registration left behind would then belong to a stranger.
	 *
	 * Unconditional on purpose: this also runs for connections rejected while
	 * still pending, which never reached the poller.  h2_poller_del() answers
	 * that case with a no-op rather than an error, so there is no condition
	 * here to get wrong.
	 */
	h2_poller_del(shard->poller, conn->base_session->client_socket);

	/* Send GOAWAY (best effort — socket may be dead) */
	nghttp2_submit_goaway(conn->ng_session, NGHTTP2_FLAG_NONE,
	                      nghttp2_session_get_last_proc_stream_id(conn->ng_session),
	                      NGHTTP2_NO_ERROR, NULL, 0);
	nghttp2_session_send(conn->ng_session);

	destroy_all_streams(conn);
	nghttp2_session_del(conn->ng_session);
	conn->ng_session = NULL;

	/* Flush undispatched queue items before zombie transition.
	 * No workers hold these — safe to free.  Must happen before
	 * the pending_requests check below, otherwise queued items
	 * would keep the connection alive as a zombie indefinitely.
	 */
	h2_flush_queue(conn);

	/* Close the session's socket and TLS */
	destroy_session(conn->base_session);
	close_socket(conn->base_session);

	/* The process-wide connection slot goes back HERE, before the zombie
	 * transition: a zombie holds memory for its in-flight workers, not a
	 * connection slot -- exactly where the old per-loop conn_count stopped
	 * counting it. */
	__sync_sub_and_fetch(&h2_conn_slots_used, 1);

	if (conn->pending_requests > 0) {
		/* Workers still hold item->conn pointers — move to zombie list.
		 * The connection struct stays alive until all responses drain.
		 */
		if (shard->zombie_count >= shard->zombie_capacity) {
			if ((shard->zombie_capacity != 0) && (shard->zombie_capacity > INT_MAX / 2)) {
				return;
			}
			new_cap = shard->zombie_capacity == 0 ? 16 : shard->zombie_capacity * 2;
			new_arr = (t_http2_connection **)realloc(
				shard->zombies, (size_t)new_cap * sizeof(t_http2_connection*));
			if (new_arr == NULL) {
				/* OOM — intentionally leak the connection struct rather than
				 * freeing it while workers still hold item->conn pointers.
				 * A small leak under OOM is safer than use-after-free.
				 */
				return;
			}
			shard->zombies = new_arr;
			shard->zombie_capacity = new_cap;
		}
		shard->zombies[shard->zombie_count++] = conn;
		return;
	}

	h2_free_connection(conn);
}

/* Remove connection from array (swap with last).
 *
 * conn_count is read by h2_event_loop_add_connection() on a worker thread,
 * so every write to it is made under conn_mutex -- as the writes in
 * process_pending_connections() already were. The connection array itself
 * belongs to the event loop thread; the lock here is about the count.
 */
static void h2_remove_connection(t_h2_shard *shard, int index) {
	pthread_mutex_lock(&shard->conn_mutex);

	if (index < shard->conn_count - 1) {
		shard->connections[index] = shard->connections[shard->conn_count - 1];
	}
	shard->conn_count--;

	pthread_mutex_unlock(&shard->conn_mutex);
}

/* Close whatever was still queued for admission.  Called with the loop
 * thread gone (joined, or this IS the loop thread on its way out), so the
 * taken array has one accessor left.  The mutex is still needed for the
 * hand-off itself: a worker may be appending under it right now, and the
 * running re-test in h2_event_loop_add_connection() only closes the window
 * together with this drain. */
static void h2_release_pending_connections(t_h2_shard *shard) {
	t_http2_connection **taken;
	int i, count;

	pthread_mutex_lock(&shard->conn_mutex);
	taken = shard->pending_conns;
	count = shard->pending_count;
	shard->pending_conns = NULL;
	shard->pending_count = 0;
	shard->pending_capacity = 0;
	pthread_mutex_unlock(&shard->conn_mutex);

	for (i = 0; i < count; i++) {
		h2_close_connection(taken[i]);
	}

	check_free(taken);
}

/* ========================================================================
 *  Event loop: add connection
 * ======================================================================== */

int h2_event_loop_add_connection(t_session *session) {
	t_http2_connection *conn, **new_arr;
	t_h2_shard *shard;
	int new_cap;

	if ((conn = (t_http2_connection*)calloc(1, sizeof(t_http2_connection))) == NULL) {
		return -1;
	}

	/* The owner, chosen once and never revisited: a connection does not
	 * migrate.  Set BEFORE h2_init_connection(), because everything the
	 * connection does from that moment on has to be able to name its shard. */
	if ((shard = h2_shard_for_new_connection()) == NULL) {
		/* Every loop has died.  Refusing here closes the connection through
		 * the caller's normal path; attaching to a dead loop would hang it. */
		check_free(conn);
		conn = NULL;
		return -1;
	}
	conn->shard = shard;

	conn->base_session = session;
	conn->created = time(NULL);
	conn->last_activity = conn->created;
	conn->flooding_timer = conn->created;
	conn->challenge_stream_id = 0;
	conn->highest_stream_id = 0;
	conn->closing = false;
	conn->pending_requests = 0;

	/* Initialize nghttp2 and send settings */
	if (h2_init_connection(conn) != 0) {
		free(conn);
		conn = NULL;
		return -1;
	}

	/* Reject new connections if the PROCESS is at capacity -- not this shard.
	 * H2_MAX_CONNECTIONS bounds the process and does not grow with the loop
	 * count.  Deliberately OUTSIDE conn_mutex: a process-wide ceiling that
	 * needed one shard's lock would need every shard's lock to be read
	 * honestly; it needs none.  Reserve-then-test, not test-then-reserve, so
	 * the count can never exceed the ceiling no matter how many workers
	 * arrive at once.  From here until the hand-over below, every exit path
	 * gives the slot back; after the hand-over it is h2_close_connection()'s
	 * to release.  There are exactly THREE such paths: the shard-died re-test
	 * and the two capacity failures on the pending array. */
	if (__sync_add_and_fetch(&h2_conn_slots_used, 1) > H2_MAX_CONNECTIONS) {
		__sync_sub_and_fetch(&h2_conn_slots_used, 1);
		nghttp2_session_del(conn->ng_session);
		check_free(conn);
		conn = NULL;
		return -1;
	}

	/* Add to pending queue (event loop will pick it up) */
	pthread_mutex_lock(&shard->conn_mutex);

	/* Ask AGAIN whether this loop is alive, now that the lock is held: the
	 * round-robin answered further up, but between the two lie
	 * h2_init_connection() and the slot reservation.  A loop that left its
	 * while() in that gap would be handed a connection nobody ever serves --
	 * not in the poller, not in connections[], no server-side timer applies.
	 * The window is closed COMPLETELY because the dying loop stores
	 * running = false and only afterwards takes this mutex to empty
	 * pending_conns: acquired after its release we read false and refuse
	 * here; acquired before, the loop's own emptying finds what we append. */
	if (__atomic_load_n(&(shard->running), __ATOMIC_SEQ_CST) == false) {
		pthread_mutex_unlock(&shard->conn_mutex);
		__sync_sub_and_fetch(&h2_conn_slots_used, 1);
		nghttp2_session_del(conn->ng_session);
		free(conn);
		conn = NULL;
		return -1;
	}

	if (shard->pending_count >= shard->pending_capacity) {
		if ((shard->pending_capacity != 0) && (shard->pending_capacity > INT_MAX / 2)) {
			pthread_mutex_unlock(&shard->conn_mutex);
			__sync_sub_and_fetch(&h2_conn_slots_used, 1);
			nghttp2_session_del(conn->ng_session);
			check_free(conn);
			conn = NULL;
			return -1;
		}
		new_cap = shard->pending_capacity == 0 ? 16 : shard->pending_capacity * 2;
		new_arr = (t_http2_connection **)realloc(
			shard->pending_conns, (size_t)new_cap * sizeof(t_http2_connection*));
		if (new_arr == NULL) {
			pthread_mutex_unlock(&shard->conn_mutex);
			__sync_sub_and_fetch(&h2_conn_slots_used, 1);
			nghttp2_session_del(conn->ng_session);
			free(conn);
			conn = NULL;
			return -1;
		}
		shard->pending_conns = new_arr;
		shard->pending_capacity = new_cap;
	}

	shard->pending_conns[shard->pending_count++] = conn;

	pthread_mutex_unlock(&shard->conn_mutex);

	/* Wake up event loop */
	if (write(shard->wakeup_pipe[1], "C", 1) == -1) {
		/* Best effort */
	}

	return 0;
}

/* ========================================================================
 *  Event loop: main thread
 * ======================================================================== */

static void drain_wakeup_pipe(t_h2_shard *shard) {
	char buf[64];
	while (read(shard->wakeup_pipe[0], buf, sizeof(buf)) > 0) {
		/* drain */
	}
}

static void process_pending_connections(t_h2_shard *shard) {
	t_http2_connection **new_arr;
	int i, new_cap;

	pthread_mutex_lock(&shard->conn_mutex);

	for (i = 0; i < shard->pending_count; i++) {
		/* Grow connection array if needed */
		if (shard->conn_count >= shard->conn_capacity) {
			if ((shard->conn_capacity != 0) && (shard->conn_capacity > INT_MAX / 2)) {
				h2_close_connection(shard->pending_conns[i]);
				continue;
			}
			new_cap = shard->conn_capacity == 0 ? H2_INITIAL_CONN_CAPACITY
			                                      : shard->conn_capacity * 2;
			new_arr = (t_http2_connection **)realloc(
				shard->connections, (size_t)new_cap * sizeof(t_http2_connection*));
			if (new_arr == NULL) {
				/* OOM — close this connection */
				h2_close_connection(shard->pending_conns[i]);
				continue;
			}
			shard->connections = new_arr;
			shard->conn_capacity = new_cap;
		}

		/* Set socket timeouts: SO_RCVTIMEO (200ms) for reads,
		 * SO_SNDTIMEO (4ms) for writes — see h2_set_socket_timeouts.
		 */
		h2_set_socket_timeouts(shard->pending_conns[i]->base_session->client_socket);

		/* Into the poller before into the array, so the array never holds a
		 * connection the poller cannot report on.  HP_IN is the resting
		 * interest; write interest is what h2_conn_refresh_interest() adds
		 * and drops from here on.  A failure here is out of memory: taken in,
		 * the connection would sit in the array and never be woken.
		 */
		if (h2_poller_add(shard->poller,
		                  shard->pending_conns[i]->base_session->client_socket,
		                  HP_IN, shard->pending_conns[i]) != 0) {
			log_error_session(shard->pending_conns[i]->base_session,
			                  "can't add the HTTP/2 socket to the event poller");
			h2_close_connection(shard->pending_conns[i]);
			continue;
		}

		shard->connections[shard->conn_count++] = shard->pending_conns[i];
	}

	shard->pending_count = 0;

	pthread_mutex_unlock(&shard->conn_mutex);
}

static void process_response_queue(t_h2_shard *shard) {
	t_h2_response_item *item, *next;
	int i;

	pthread_mutex_lock(&shard->response_mutex);
	item = shard->response_head;
	shard->response_head = NULL;
	shard->response_tail = NULL;
	pthread_mutex_unlock(&shard->response_mutex);

	while (item != NULL) {
		next = item->next;

		if (item->conn->ng_session == NULL) {
			/* Connection is a zombie (socket/TLS already closed).
			 * Discard the response — we can't send it anymore.
			 */
			item->conn->pending_requests--;
			item->conn->inflight_workers--;
			free(item->response_buf);
			item->response_buf = NULL;
		} else {
			/* Apply any per-directory throttle here, on the event-loop thread —
			 * the only thread that reads conn->base_session->throttle (in
			 * h2_send_callback).  Keep the smallest non-zero rate seen across the
			 * connection's streams, matching the old worker-side logic but now
			 * race-free.  Set before submit so the first send is throttled. */
			if (item->throttle > 0) {
				if ((item->conn->base_session->throttle == 0) ||
				    (item->throttle < item->conn->base_session->throttle)) {
					item->conn->base_session->throttle = item->throttle;
				}
			}

			/* Submit response to nghttp2 — ownership of response_buf transfers */
			if (h2_submit_response_from_buf(item->conn, item->stream_id,
			                             item->response_buf, item->response_size,
			                             item->response_truncated, item->request_method,
			                             item->return_code) != 0) {
				/* submit failed — response_buf freed inside h2_submit_response_from_buf */
			}
			item->response_buf = NULL;  /* Ownership transferred */

			item->conn->pending_requests--;
			item->conn->inflight_workers--;

			/* BanOnFlooding, the h2 side.  The h1.1 counter is never
			 * reached here -- parse_request() and the serve_client() loop
			 * do not run for h2 -- so this path counts for itself: per
			 * CONNECTION, on the loop thread that owns the fields, and the
			 * verdict falls AFTER the response, exactly where h1.1 places
			 * it in its connection loop (workers.c).  The configured number
			 * is multiplied by H2_FLOOD_CONNECTION_FACTOR (http2.h): one
			 * h2 connection multiplexes what an h1.1 browser spreads over
			 * several, so the same line treats both protocols alike.
			 *
			 * The window belongs to the connection's address.  The big 12.4
			 * hands the worker's RESOLVED address over instead, because CDN
			 * support and HideProxy-over-h2 can make it differ there; this
			 * tree has neither -- the worker session's ip_address is always
			 * the connection's -- so the plumbing would move a value that
			 * cannot change.  Whoever adds either feature must move the
			 * window to the resolved address (finding c12). */
			if (shard->config->ban_on_flooding > 0) {
				time_t flood_now = time(NULL);

				item->conn->flood_requests++;

				if (flood_limit_reached(shard->config, item->conn->flooding_timer,
				                        item->conn->flood_requests, flood_now,
				                        H2_FLOOD_CONNECTION_FACTOR)) {
					t_session flood_session;

					/* A stack session carrying config, host and the address
					 * the verdict is about -- the shape monitor_count_ban()
					 * and log_system_session() expect, without borrowing the
					 * base_session's unrelated request state. */
					memset(&flood_session, 0, sizeof(t_session));
					flood_session.config = shard->config;
					flood_session.host = flood_session.config->first_host;
					flood_session.ip_address = item->conn->base_session->ip_address;
					flood_session.remote_port = item->conn->base_session->remote_port;
					flood_session.method = "-";
					flood_session.uri = "-";
					flood_session.http_version = "HTTP/2.0";

					if (ip_allowed(&(flood_session.ip_address), flood_session.config->banlist_mask) != deny) {
						ban_ip(&(flood_session.ip_address), flood_session.config->ban_on_flooding, flood_session.config->kick_on_ban);
						log_system_session(&flood_session, "Client banned because of flooding");
#ifdef ENABLE_MONITOR
						if (flood_session.config->monitor_enabled) {
							monitor_count_ban(&flood_session);
						}
#endif
						/* Parity with h1.1, which sets keep_alive = false and
						 * ends the connection at the ban (workers.c).  Marking
						 * closing sends GOAWAY, refuses new streams and tears
						 * the connection down once its in-flight requests
						 * drain -- so the offending connection stops being
						 * served, not only the next one the ban list refuses
						 * at accept.  Only when the ban actually applied,
						 * exactly as h1.1 closes only inside its ip_allowed
						 * check. */
						h2_mark_closing(item->conn);
					}

					/* Window restart: while the connection drains its
					 * in-flight streams after the ban above, each still
					 * arrives here, and without the restart every one would
					 * re-ban and re-log.  h1.1 needs no equal because it
					 * stops reading the moment keep_alive goes false. */
					item->conn->flood_requests = 0;
					item->conn->flooding_timer = flood_now;
				}
			}

			/* Deferred logging */
			/*
			if ((item->log_request) && (item->log_uri != NULL)) {
				log_system(shard->config, "HTTP/2 %s %s %d",
				           item->request_method == GET ? "GET" :
				           item->request_method == QUERY ? "QUERY" :
				           item->request_method == POST ? "POST" :
				           item->request_method == HEAD ? "HEAD" : "?",
				           item->log_uri, item->return_code);
			}
			*/
		}

		free(item->log_uri);
		item->log_uri = NULL;
		free(item);
		item = next;
	}

	/* Flush all connections that may have pending response frames */
	for (i = 0; i < shard->conn_count; i++) {
		if (nghttp2_session_want_write(shard->connections[i]->ng_session)) {
			if (nghttp2_session_send(shard->connections[i]->ng_session) != 0) {
				h2_mark_closing(shard->connections[i]);
			}
		}
	}

	/* Free zombie connections whose pending_requests have drained to 0 */
	for (i = shard->zombie_count - 1; i >= 0; i--) {
		if (shard->zombies[i]->pending_requests <= 0) {
			h2_free_connection(shard->zombies[i]);
			/* Swap with last */
			if (i < shard->zombie_count - 1) {
				shard->zombies[i] = shard->zombies[shard->zombie_count - 1];
			}
			shard->zombie_count--;
		}
	}
}

static void h2_read_and_process(t_http2_connection *conn) {
	char buf[H2_READ_BUFFER_SIZE];
	int n;
	bool got_data = false;

	/* Non-blocking read: h2_tls_receive() returns 0 on WANT_READ
	 * instead of blocking the entire event loop.
	 */
	do {
		n = h2_tls_receive(&(conn->base_session->tls_context), buf, sizeof(buf));
		if (n < 0) {
			h2_mark_closing(conn);
			return;
		}
		if (n == 0) {
			/* Partial TLS record or peer close — come back later */
			break;
		}

		got_data = true;

		if (nghttp2_session_mem_recv(conn->ng_session, (uint8_t*)buf, (size_t)n) < 0) {
			h2_mark_closing(conn);
			return;
		}
	} while (tls_pending(&(conn->base_session->tls_context)) > 0);

	/* Refresh the idle timer only on real forward progress, NOT on every
	 * readable event: a byte trickle that never completes a TLS record makes
	 * the socket POLLIN-readable without got_data, and refreshing here would
	 * let it hold the connection open forever (slowloris). */
	if (got_data) {
		conn->last_activity = time(NULL);
	}

	/* Send any pending frames (SETTINGS ACK, WINDOW_UPDATE, responses) */
	if ((got_data) || (nghttp2_session_want_write(conn->ng_session))) {
		if (nghttp2_session_send(conn->ng_session) != 0) {
			h2_mark_closing(conn);
		}
	}

	/* Reap a session nghttp2 has finished with.  Its documented contract: when
	 * both want_read() and want_write() return 0 the connection should be
	 * dropped (e.g. it emitted a soft GOAWAY and all streams are gone).  Without
	 * this the connection lingers until the idle timeout while the client holds
	 * the socket open, needlessly pinning a slot. */
	if ((conn->ng_session != NULL) &&
	    (nghttp2_session_want_read(conn->ng_session) == 0) &&
	    (nghttp2_session_want_write(conn->ng_session) == 0)) {
		h2_mark_closing(conn);
	}
}

static void h2_check_timeouts(t_h2_shard *shard) {
	t_http2_connection *conn;
	time_t now;
	int i;

	now = time(NULL);

	for (i = shard->conn_count - 1; i >= 0; i--) {
		conn = shard->connections[i];

		/* Force quit (ban, server shutdown).
		 * ban_ip() with kick_on_ban sets this from a worker thread, under
		 * client_mutex[] which this loop does not hold; the flag carries its
		 * own ordering instead (session.h).  Seeing it one poll cycle late is
		 * still possible and still harmless -- what is gone is the unordered
		 * access ThreadSanitizer reported.
		 */
		if (__atomic_load_n(&(conn->base_session->force_quit), __ATOMIC_ACQUIRE)) {
			h2_close_connection(conn);
			h2_remove_connection(shard, i);
			continue;
		}

		/* Closing flag set by I/O error or peer disconnect */
		if (conn->closing) {
			/* Wait for pending worker responses, but not forever */
			if ((conn->pending_requests <= 0) ||
			    ((now - conn->closing_since) > H2_CLOSING_TIMEOUT)) {
				h2_close_connection(conn);
				h2_remove_connection(shard, i);
			}
			continue;
		}

		/* Idle timeout: apply time_for_1st_request / time_for_request
		 * from the binding config (mirrors fetch_request() deadline logic
		 * for HTTP/1.x).  Falls back to H2_IDLE_TIMEOUT if both are 0.
		 */
		int idle_timeout;
		time_t reference;

		if ((conn->requests_served == 0) && (conn->active_streams == 0)) {
			/* Connected but no request stream has opened yet: an ABSOLUTE
			 * deadline from accept defeats a byte trickle that keeps the socket
			 * readable without ever forming a request (slowloris).  time_for_1st
			 * _request here bounds the wait for the first HEADERS, mirroring
			 * HTTP/1.1 where it bounds the request header — NOT the body. */
			idle_timeout = conn->base_session->binding->time_for_1st_request;
			reference = conn->created;
		} else {
			/* A stream is open (or a request has completed): key off forward
			 * progress (last_activity, refreshed on every DATA frame) so a
			 * slow-but-steady upload/download is not truncated.  Using the
			 * absolute deadline here would abort a legitimate large first upload
			 * mid-stream, since requests_served stays 0 until END_STREAM. */
			idle_timeout = conn->base_session->binding->time_for_request;
			reference = conn->last_activity;
		}

		if (idle_timeout <= 0) {
			idle_timeout = H2_IDLE_TIMEOUT;
		}

		if ((conn->pending_requests == 0) &&
		    ((now - reference) > idle_timeout)) {
			h2_close_connection(conn);
			h2_remove_connection(shard, i);
			continue;
		}
	}
}

/* What the poller should wake this connection for.
 *
 * The three inputs are exactly the ones the pollfd builder used to read, and
 * the rule is unchanged: always readable, additionally writable when a write
 * is blocked or nghttp2 has something queued -- UNLESS the connection is
 * timer-throttled, because its socket IS writable and asking for HP_OUT
 * during the throttle window spins the loop at 100% of a core.  The 1000ms
 * wait timeout bounds the resume latency to the 1s window.
 *
 * ONE PLACE, and that is the point.  With poll(2) the mask is re-read out of
 * the poller on every wait, so refreshing once per cycle (below) cannot go
 * stale.  With epoll and kqueue the mask sits in the KERNEL, and this
 * function is the only thing between a state change and a connection that
 * never wakes again.  h2_poller_mod() is free when the mask is unchanged,
 * which is what makes "call it whenever in doubt" the affordable answer
 * rather than a reasoning exercise about which edges may be skipped.
 */
static void h2_conn_refresh_interest(t_http2_connection *conn, time_t now) {
	short events = HP_IN;

	if ((now >= conn->throttle_until) &&
	    ((conn->write_blocked) ||
	     ((conn->ng_session != NULL) &&
	      nghttp2_session_want_write(conn->ng_session)))) {
		events |= HP_OUT;
	}

	h2_poller_mod(conn->shard->poller, conn->base_session->client_socket, events, conn);
}

static void *h2_event_loop_thread(void *arg) {
	t_h2_shard *shard = (t_h2_shard*)arg;
	t_h2_pevent *tmp;
	t_http2_connection *conn;
	int want_events, nevents, i, total_pending;
	time_t now, deadline;
	const char *died = NULL;
	int died_errno = 0;

	while (__atomic_load_n(&shard->running, __ATOMIC_SEQ_CST)) {
		/* One wait may report every registered descriptor, so the batch is
		 * sized from the poller's own count rather than from conn_count.  The
		 * two agree today, but only the poller knows for certain what it will
		 * hand back, and a batch one entry short would silently defer a ready
		 * connection to the next round.  Nothing registers between here and
		 * the wait below -- adds happen in process_pending_connections(),
		 * which runs after it. */
		want_events = h2_poller_count(shard->poller);
		if (shard->events_capacity < want_events) {
			if ((tmp = (t_h2_pevent*)realloc(shard->events,
			     (size_t)want_events * sizeof(t_h2_pevent))) == NULL) {
				died = "growing the event batch";
				died_errno = errno;
				break;
			}
			shard->events = tmp;
			shard->events_capacity = want_events;
		}

		/* Refresh write interest, once per cycle for every connection -- the
		 * same recomputation, at the same point, that the pollfd builder did.
		 * See h2_conn_refresh_interest() for why this loop is the one place
		 * the interest is decided. */
		now = time(NULL);
		for (i = 0; i < shard->conn_count; i++) {
			h2_conn_refresh_interest(shard->connections[i], now);
		}

		/* 1000ms timeout for idle checks */
		if ((nevents = h2_poller_wait(shard->poller, shard->events,
		     shard->events_capacity, 1000)) < 0) {
			if (errno == EINTR) {
				continue;
			}
			died = "h2_poller_wait";
			died_errno = errno;
			break;
		}

		/* Wakeup pipe: new connections queued.  It is the one registration
		 * carrying a NULL data pointer, and it is served before the connection
		 * I/O below, exactly as the pollfds[0] test was. */
		for (i = 0; i < nevents; i++) {
			if ((shard->events[i].data == NULL) && (shard->events[i].events & HP_IN)) {
				drain_wakeup_pipe(shard);
				process_pending_connections(shard);
				break;
			}
		}

		/* Process worker responses every cycle (wakeup byte may be
		 * coalesced or lost if pipe was already readable).
		 */
		process_response_queue(shard);
		h2_drain_dispatch_queue(shard);  /* drain point 1: workers finished, slots free */

		/* Connection I/O.  The batch is a snapshot taken by the wait above,
		 * so connections that process_pending_connections() has just admitted
		 * are not in it and are first served next round -- the same exclusion
		 * the old "iterate only nfds - 1 entries" comment described, now a
		 * property of the batch rather than a bound to be got right.
		 *
		 * NOTHING IN HERE MAY REMOVE A CONNECTION.  The entries carry conn
		 * pointers, so freeing one while later entries still reference it is a
		 * use-after-free.  h2_read_and_process() and h2_mark_closing() only
		 * set flags; the actual close happens in h2_check_timeouts(), below
		 * the batch.  The index loop this replaces needed the very same
		 * discipline, because h2_remove_connection() swaps with the last
		 * element and would have shifted a connection under the iteration.
		 */
		for (i = 0; i < nevents; i++) {
			if ((conn = (t_http2_connection*)shard->events[i].data) == NULL) {
				continue;  /* the wakeup pipe, already served above */
			}

			/* HP_IN: data available — read and process */
			if (shard->events[i].events & HP_IN) {
				h2_read_and_process(conn);
			}

			/* HP_OUT: socket ready for writing — flush pending data */
			if (shard->events[i].events & HP_OUT) {
				conn->write_blocked = false;
				if ((conn->ng_session != NULL) &&
				    (nghttp2_session_want_write(conn->ng_session))) {
					if (nghttp2_session_send(conn->ng_session) != 0) {
						h2_mark_closing(conn);
					}
				}
			}

			/* HP_HUP/HP_ERR: peer disconnect or error */
			if (shard->events[i].events & (HP_HUP | HP_ERR)) {
				h2_mark_closing(conn);
			}
		}

		h2_drain_dispatch_queue(shard);  /* drain point 2: new items enqueued by I/O above */

		/* Idle timeout + force_quit + closing cleanup */
		h2_check_timeouts(shard);

		/* Graceful drain: send GOAWAY, wait for pending requests */
		if (__atomic_load_n(&shard->draining, __ATOMIC_SEQ_CST)) {
			if (__atomic_load_n(&shard->goaway_sent, __ATOMIC_SEQ_CST) == false) {
				for (i = 0; i < shard->conn_count; i++) {
					conn = shard->connections[i];
					if ((conn->ng_session != NULL) && (!conn->closing)) {
						nghttp2_submit_goaway(conn->ng_session,
						    NGHTTP2_FLAG_NONE,
						    nghttp2_session_get_last_proc_stream_id(conn->ng_session),
						    NGHTTP2_NO_ERROR, NULL, 0);
						nghttp2_session_send(conn->ng_session);
						h2_mark_closing(conn);
					}
				}
				__atomic_store_n(&shard->goaway_sent, true, __ATOMIC_SEQ_CST);
			}

			/* Process worker responses that arrived during drain */
			process_response_queue(shard);
			h2_drain_dispatch_queue(shard);  /* drain point 3: graceful shutdown */

			/* Count remaining pending requests */
			total_pending = 0;
			for (i = 0; i < shard->conn_count; i++) {
				total_pending += shard->connections[i]->pending_requests;
			}
			for (i = 0; i < shard->zombie_count; i++) {
				total_pending += shard->zombies[i]->pending_requests;
			}

			if ((total_pending == 0) || (time(NULL) >= __atomic_load_n(&shard->drain_deadline, __ATOMIC_SEQ_CST))) {
				__atomic_store_n(&shard->running, false, __ATOMIC_SEQ_CST);
			}
		}
	}

	/* An abnormal exit gets its OWN line, and running is cleared before it:
	 * clearing the flag is what takes this shard out of
	 * h2_shard_for_new_connection(), so no reader of the log can see the
	 * shard handed out as alive after the line that says it is not.  A
	 * normal shutdown cleared the flag before the loop ended. */
	if (died != NULL) {
		__atomic_store_n(&(shard->running), false, __ATOMIC_SEQ_CST);
		log_system(shard->config, "HTTP/2 event loop %d ABORTED: %s: %s -- this loop takes no further connections",
		           shard->index, died, strerror(died_errno));
	}

	/* What this loop was holding when it stopped.  Two audiences: an operator
	 * sees what each loop dropped at shutdown, and a test sees the
	 * DISTRIBUTION over the loops, which is otherwise invisible from outside
	 * the process.  On the loop thread, BEFORE the teardown below, so the
	 * number is exact and costs no synchronisation.  Byte-identical to the
	 * big 12.4's line on purpose: tests/h2_shard reads the connection count
	 * out of it. */
	log_system(shard->config, "HTTP/2 event loop %d stopped: %d connections, %d pending, %d zombies",
	           shard->index, shard->conn_count, shard->pending_count, shard->zombie_count);

	/* Whatever was still queued for admission: what a worker handed over
	 * between the loop's last process_pending_connections() and its exit --
	 * after a death, plus whatever arrived before the re-test in
	 * h2_event_loop_add_connection() saw running == false. */
	h2_release_pending_connections(shard);

	/* Shutdown: close all remaining connections */
	while (shard->conn_count > 0) {
		h2_close_connection(shard->connections[0]);
		h2_remove_connection(shard, 0);
	}

	/* Settle the response queue: every connection is closed, so each item
	 * takes the zombie branch and its tail reaps the zombies that reach
	 * zero.  A LOOP, not one call, because a worker that was still running
	 * pushes its response after a single call would have returned.  This
	 * matters most after a death: the shutdown functions may not run for
	 * days, and until the responses drain the zombies hold their memory. */
	deadline = time(NULL) + H2_DEATH_DRAIN_TIMEOUT;
	for (;;) {
		process_response_queue(shard);

		total_pending = 0;
		for (i = 0; i < shard->zombie_count; i++) {
			total_pending += shard->zombies[i]->pending_requests;
		}

		if ((total_pending == 0) || (time(NULL) >= deadline)) {
			break;
		}

		usleep(50 * 1000);
	}

	return NULL;
}

/* ========================================================================
 *  Event loop init / shutdown
 * ======================================================================== */

/* Bring ONE shard up: pipe, poller, mutexes, thread.  Returns 0, or -1 with
 * the shard left exactly as calloc left it -- every descriptor closed, every
 * pointer NULL, running false.  ONE failure exit that undoes in reverse
 * order of construction, so "did I clean everything up" is answered by
 * reading one block.
 *
 * running is set true immediately before pthread_create and put back on
 * failure, so it means exactly "this shard has a loop thread" -- which is
 * what h2_shard_for_new_connection() and the shutdown fan-outs assume. */
static int h2_shard_bring_up(t_h2_shard *shard, int index, t_config *config) {
	pthread_attr_t attr;
	bool conn_mutex_ready = false, response_mutex_ready = false, attr_ready = false;
	int flags;

	memset(shard, 0, sizeof(*shard));
	shard->index = index;
	shard->config = config;
	shard->wakeup_pipe[0] = -1;
	shard->wakeup_pipe[1] = -1;

	if (pipe(shard->wakeup_pipe) != 0) {
		shard->wakeup_pipe[0] = shard->wakeup_pipe[1] = -1;
		goto fail;
	}

	/* Make both ends non-blocking.
	 * Read end: for drain_wakeup_pipe().
	 * Write end: if the pipe buffer is full (all workers writing at once),
	 * write() returns EAGAIN instead of blocking the worker thread.
	 * EAGAIN is safe to ignore: the pipe already has data, so the event
	 * loop will wake up regardless.
	 */
	flags = fcntl(shard->wakeup_pipe[0], F_GETFL, 0);
	if (flags != -1) {
		fcntl(shard->wakeup_pipe[0], F_SETFL, flags | O_NONBLOCK);
	}
	flags = fcntl(shard->wakeup_pipe[1], F_GETFL, 0);
	if (flags != -1) {
		fcntl(shard->wakeup_pipe[1], F_SETFL, flags | O_NONBLOCK);
	}

	/* The poller, and the wakeup pipe as its first registration.  NULL is the
	 * pipe's data pointer and is what the loop recognises it by -- every other
	 * registration carries a t_http2_connection*.  Both happen here, before
	 * the thread exists, so the loop never finds an empty poller.
	 */
	if ((shard->poller = h2_poller_create()) == NULL) {
		goto fail;
	}

	if (h2_poller_add(shard->poller, shard->wakeup_pipe[0], HP_IN, NULL) != 0) {
		goto fail;
	}

	if (pthread_mutex_init(&shard->conn_mutex, NULL) != 0) {
		goto fail;
	}
	conn_mutex_ready = true;

	if (pthread_mutex_init(&shard->response_mutex, NULL) != 0) {
		goto fail;
	}
	response_mutex_ready = true;

	if (pthread_attr_init(&attr) != 0) {
		goto fail;
	}
	attr_ready = true;

	__atomic_store_n(&shard->running, true, __ATOMIC_SEQ_CST);

	if (pthread_create(&shard->thread, &attr, h2_event_loop_thread, shard) != 0) {
		__atomic_store_n(&shard->running, false, __ATOMIC_SEQ_CST);
		goto fail;
	}
	__atomic_store_n(&shard->thread_started, true, __ATOMIC_SEQ_CST);

	pthread_attr_destroy(&attr);

	return 0;

fail:
	if (attr_ready) {
		pthread_attr_destroy(&attr);
	}
	if (response_mutex_ready) {
		pthread_mutex_destroy(&shard->response_mutex);
	}
	if (conn_mutex_ready) {
		pthread_mutex_destroy(&shard->conn_mutex);
	}
	if (shard->poller != NULL) {
		h2_poller_destroy(shard->poller);
		shard->poller = NULL;
	}
	if (shard->wakeup_pipe[0] != -1) {
		close(shard->wakeup_pipe[0]);
		shard->wakeup_pipe[0] = -1;
	}
	if (shard->wakeup_pipe[1] != -1) {
		close(shard->wakeup_pipe[1]);
		shard->wakeup_pipe[1] = -1;
	}
	__atomic_store_n(&shard->running, false, __ATOMIC_SEQ_CST);

	return -1;
}

/* Defined below, next to its graceful twin.  Declared here because the
 * unwind in h2_event_loop_init() tears a half-built fan-out down through
 * the same function every normal shutdown uses. */
static void h2_shard_shutdown(t_h2_shard *shard);

int h2_event_loop_init(t_config *config) {
	int s, t;

	/* The count comes from H2EventLoops, validated in serverconfig.c against
	 * MAX_H2_EVENT_LOOPS and defaulting to 1.  Nothing here re-checks it: a
	 * second range test in a second place is a second thing to get out of
	 * step, and the parser refuses a bad value rather than passing one on. */
	if ((h2_shards = (t_h2_shard*)calloc((size_t)config->h2_event_loops, sizeof(t_h2_shard))) == NULL) {
		return -1;
	}
	h2_shard_count = config->h2_event_loops;

	/* One line per start -- without it an operator never learns that "cpus"
	 * picked the SMT-doubled count on this machine, which is why it is
	 * written even for a fixed number.  h2_cpus_online was captured at
	 * configuration time, before the privilege drop (serverconfig.c), so
	 * nothing is asked of the kernel here. */
	if (config->h2_cpus_online >= 1) {
		log_system(config, "HTTP/2: %d event loop(s) (%s), %ld CPUs online",
		           h2_shard_count,
		           config->h2_event_loops_cpus ? "H2EventLoops = cpus" : "configured",
		           config->h2_cpus_online);
	} else {
		log_system(config, "HTTP/2: %d event loop(s) (%s), CPU count unavailable",
		           h2_shard_count,
		           config->h2_event_loops_cpus ? "H2EventLoops = cpus, fell back to 1" : "configured");
	}

	for (s = 0; s < h2_shard_count; s++) {
		if (h2_shard_bring_up(&h2_shards[s], s, config) == 0) {
			continue;
		}

		/* ABORT.  A shard that will not start does not become a smaller
		 * server, it becomes a topology nobody configured: N is what every
		 * other decision is made against.  The already-started shards go
		 * down through the same h2_shard_shutdown() a normal shutdown uses;
		 * a shard the loop never reached is untouched calloc memory with
		 * thread_started false, which that function returns early on. */
		fprintf(stderr, "HTTP/2 event loop %d of %d failed to start; not starting the server.\n",
		        s, h2_shard_count);
		log_system(config, "HTTP/2 event loop %d of %d failed to start; not starting the server",
		           s, h2_shard_count);

		for (t = 0; t < s; t++) {
			h2_shard_shutdown(&h2_shards[t]);
		}

		check_free(h2_shards);
		h2_shards = NULL;
		h2_shard_count = 0;

		return -1;
	}

	return 0;
}

static void h2_shard_shutdown(t_h2_shard *shard) {
	t_h2_response_item *item, *next;
	int i, total_pending;
	time_t deadline;

	/* thread_started, not running: the question is "is there a thread to
	 * join and state to take apart", and running answers a different one --
	 * a loop that died cleared it itself to leave the rotation, and on
	 * running the two cases read the same.  A shard the init fan-out never
	 * reached is untouched calloc memory and returns here. */
	if ((__atomic_load_n(&shard->thread_started, __ATOMIC_SEQ_CST) == false) ||
	    __atomic_load_n(&shard->shutdown_done, __ATOMIC_SEQ_CST)) {
		return;
	}
	__atomic_store_n(&shard->shutdown_done, true, __ATOMIC_SEQ_CST);

	/* 1. Signal: tell event loop to stop accepting new work */
	__atomic_store_n(&shard->running, false, __ATOMIC_SEQ_CST);

	/* Wake up event loop so it exits */
	if (shard->wakeup_pipe[1] != -1) {
		if (write(shard->wakeup_pipe[1], "Q", 1) == -1) {
			/* Best effort */
		}
	}

	pthread_join(shard->thread, NULL);

	/* Whatever was still queued for admission: the loop thread drained the
	 * queue itself on its way out, but a worker may have appended between
	 * that drain and this join.  The loop is joined, so this array has one
	 * accessor left and it is this thread. */
	h2_release_pending_connections(shard);

	/* 2. Drain: wait for pending requests to finish before destroying
	 * synchronization primitives.  Workers may still hold locks;
	 * destroying mutexes while locked is undefined behavior.
	 * 10s timeout: allows slow CGI/reverse-proxy workers to finish
	 * while still bounding shutdown time.
	 */
	deadline = time(NULL) + 10;
	for (;;) {
		/* Drain completed responses so pending_requests decrements */
		pthread_mutex_lock(&shard->response_mutex);
		item = shard->response_head;
		shard->response_head = NULL;
		shard->response_tail = NULL;
		pthread_mutex_unlock(&shard->response_mutex);

		while (item != NULL) {
			next = item->next;
			item->conn->pending_requests--;
			free(item->response_buf);
			item->response_buf = NULL;
			free(item->log_uri);
			item->log_uri = NULL;
			free(item);
			item = next;
		}

		/* Count remaining pending requests across all connections */
		total_pending = 0;
		for (i = 0; i < shard->conn_count; i++) {
			total_pending += shard->connections[i]->pending_requests;
		}
		for (i = 0; i < shard->zombie_count; i++) {
			total_pending += shard->zombies[i]->pending_requests;
		}

		if ((total_pending == 0) || (time(NULL) >= deadline)) {
			break;
		}

		usleep(50 * 1000);  /* 50ms between drain attempts */
	}

	/* 3. Wait for THIS SHARD's workers to finish before destroying mutexes.
	 * Workers call pthread_mutex_lock(&response_mutex) to enqueue
	 * responses — destroying it while locked is undefined behavior.
	 * The per-shard counter, not h2_active_workers: the global one also
	 * counts the workers of shards this fan-out has not reached yet, whose
	 * still-running loops keep dispatching -- waiting on it here would time
	 * out under load and leak this shard's state for someone else's workers.
	 */
	deadline = time(NULL) + 5;
	while (__sync_fetch_and_add(&(shard->active_workers), 0) > 0) {
		if (time(NULL) >= deadline) {
			break;
		}
		usleep(10 * 1000);
	}

	/* 4. Free and destroy only when the wait really reached zero.  The wait
	 * above gives up on a deadline, and a worker blocked in a slow backend
	 * outlives it -- it will still lock response_mutex in h2_push_response()
	 * and still hold item->conn.  Destroying the mutex under it is undefined
	 * behavior and freeing the connection is a use-after-free, so past the
	 * deadline this leaks instead: a leak at process exit costs nothing, a
	 * UAF costs a crash or silent corruption.  Same branch as in
	 * h2_shard_graceful_shutdown(); the order is the big 12.4's
	 * (master:src/http2.c, h2_shard_shutdown).  The pipes close only on
	 * this branch too: once the fd number is free another thread's open()
	 * can claim it, and a stale worker write() then lands in an unrelated
	 * descriptor. */
	if (__sync_fetch_and_add(&(shard->active_workers), 0) == 0) {
		pthread_mutex_destroy(&shard->conn_mutex);
		pthread_mutex_destroy(&shard->response_mutex);

		for (i = 0; i < shard->zombie_count; i++) {
			h2_free_connection(shard->zombies[i]);
		}
		shard->zombie_count = 0;

		if (shard->wakeup_pipe[0] != -1) {
			close(shard->wakeup_pipe[0]);
			shard->wakeup_pipe[0] = -1;
		}
		if (shard->wakeup_pipe[1] != -1) {
			close(shard->wakeup_pipe[1]);
			shard->wakeup_pipe[1] = -1;
		}
	} else {
		fprintf(stderr, "HTTP/2 event loop %d: a worker of this loop is still active at shutdown; leaking its connection state to avoid use-after-free.\n",
		        shard->index);
	}

	/* The connection/pending/zombie ARRAYS are event-loop-only; the joined
	 * event loop no longer touches them and workers never hold the array
	 * pointers (only individual conn structs), so they are safe to free on
	 * either path.  The poller and its event batch are in that same group:
	 * no worker has ever held a reference to either -- and the poller goes
	 * down only HERE, after the pthread_join() above, never before it. */
	check_free(shard->connections);
	shard->connections = NULL;
	check_free(shard->pending_conns);
	shard->pending_conns = NULL;
	check_free(shard->zombies);
	shard->zombies = NULL;
	h2_poller_destroy(shard->poller);
	shard->poller = NULL;
	check_free(shard->events);
	shard->events = NULL;
	shard->events_capacity = 0;
}

void h2_event_loop_shutdown(void) {
	int s;

	for (s = 0; s < h2_shard_count; s++) {
		h2_shard_shutdown(&h2_shards[s]);
	}
}

static void h2_shard_graceful_shutdown(t_h2_shard *shard, int timeout_seconds) {
	t_h2_response_item *item, *next;
	int i;
	time_t worker_deadline;

	/* thread_started, not running -- see the twin above. */
	if ((__atomic_load_n(&shard->thread_started, __ATOMIC_SEQ_CST) == false) ||
	    __atomic_load_n(&shard->shutdown_done, __ATOMIC_SEQ_CST)) {
		return;
	}
	__atomic_store_n(&shard->shutdown_done, true, __ATOMIC_SEQ_CST);

	/* Tell the event loop to start draining.
	 * Write order matters: drain_deadline before draining, so the event
	 * loop never reads draining==true with a stale drain_deadline.
	 */
	__atomic_store_n(&shard->drain_deadline, time(NULL) + timeout_seconds, __ATOMIC_SEQ_CST);
	__atomic_store_n(&shard->goaway_sent, false, __ATOMIC_SEQ_CST);
	__atomic_store_n(&shard->draining, true, __ATOMIC_SEQ_CST);

	/* Wake event loop so it processes the drain flag immediately */
	if (shard->wakeup_pipe[1] != -1) {
		if (write(shard->wakeup_pipe[1], "G", 1) == -1) {
			/* Best effort */
		}
	}

	/* Wait for event loop thread to finish draining and exit */
	pthread_join(shard->thread, NULL);
	__atomic_store_n(&shard->running, false, __ATOMIC_SEQ_CST);

	/* Whatever was still queued for admission -- see the twin above. */
	h2_release_pending_connections(shard);

	/* Wait for THIS SHARD's in-flight workers to finish BEFORE freeing anything they may
	 * still reference: zombie connections (item->conn / base_session), the
	 * response mutex, and the wakeup pipe.  A worker on a slow upstream can
	 * outlive the event loop; freeing a zombie connection or destroying the
	 * response mutex while a worker is live is a use-after-free.  If the wait
	 * times out we deliberately LEAK the worker-referenced state instead of
	 * freeing it (leak >> UAF) — this is process shutdown, so the OS reclaims
	 * everything at exit anyway.
	 */
	worker_deadline = time(NULL) + 5;
	while (__sync_fetch_and_add(&(shard->active_workers), 0) > 0) {
		if (time(NULL) >= worker_deadline) {
			break;
		}
		usleep(10 * 1000);
	}

	if (__sync_fetch_and_add(&(shard->active_workers), 0) == 0) {
		/* All workers finished — safe to release worker-referenced state. */
		for (i = 0; i < shard->zombie_count; i++) {
			h2_free_connection(shard->zombies[i]);
		}
		shard->zombie_count = 0;

		if (shard->wakeup_pipe[0] != -1) {
			close(shard->wakeup_pipe[0]);
			shard->wakeup_pipe[0] = -1;
		}
		if (shard->wakeup_pipe[1] != -1) {
			close(shard->wakeup_pipe[1]);
			shard->wakeup_pipe[1] = -1;
		}

		pthread_mutex_destroy(&shard->conn_mutex);
		pthread_mutex_destroy(&shard->response_mutex);

		item = shard->response_head;
		while (item != NULL) {
			next = item->next;
			free(item->response_buf);
			item->response_buf = NULL;
			free(item->log_uri);
			item->log_uri = NULL;
			free(item);
			item = next;
		}
		shard->response_head = NULL;
		shard->response_tail = NULL;
	} else {
		/* A worker is still running past the grace window.  Leak its
		 * referenced state (zombie connections, response mutex, wakeup pipe,
		 * pending responses) rather than free/destroy it under a live thread.
		 */
		fprintf(stderr, "HTTP/2 event loop %d: a worker of this loop is still active at shutdown; leaking its connection state to avoid use-after-free.\n",
		        shard->index);
	}

	/* The connection/pending/zombie ARRAYS are event-loop-only; the joined
	 * event loop no longer touches them and workers never hold the array
	 * pointers (only individual conn structs), so they are safe to free on
	 * either path.
	 */
	if (shard->connections != NULL) {
		check_free(shard->connections);
		shard->connections = NULL;
	}

	if (shard->pending_conns != NULL) {
		check_free(shard->pending_conns);
		shard->pending_conns = NULL;
	}

	if (shard->zombies != NULL) {
		check_free(shard->zombies);
		shard->zombies = NULL;
	}

	/* The poller and its event batch are in that same group: event-loop-only,
	 * never referenced by a worker. */
	h2_poller_destroy(shard->poller);
	shard->poller = NULL;

	if (shard->events != NULL) {
		check_free(shard->events);
		shard->events = NULL;
		shard->events_capacity = 0;
	}
}

void h2_graceful_shutdown(int timeout_seconds) {
	int s;

	for (s = 0; s < h2_shard_count; s++) {
		h2_shard_graceful_shutdown(&h2_shards[s], timeout_seconds);
	}
}

#endif /* ENABLE_HTTP2 */
