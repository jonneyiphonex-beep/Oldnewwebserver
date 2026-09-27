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
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <zlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <syslog.h>
#include "global.h"
#include "liblist.h"
#include "libfs.h"
#include "libstr.h"
#include "log.h"
#include "memdbg.h"

#define BUFFER_SIZE        2 * KILOBYTE
#define TIMESTAMP_SIZE    40
#define LOGFILE_OPEN_TIME 30
#define GZIP_BUFFER_SIZE   8 * KILOBYTE
#define IP_ADDRESS_SIZE MAX_IP_STR_LEN + 1

#ifdef CYGWIN
#define EOL "\r\n"
#else
#define EOL "\n"
#endif

static pthread_mutex_t accesslog_mutex;
static int day_of_year;

/* Initialize log module
 */
int init_log_module(t_config *config) {
	time_t now;
	struct tm s;

	if (pthread_mutex_init(&accesslog_mutex, NULL) != 0) {
		return -1;
	}

	now = time(NULL);
	localtime_r(&now, &s);
	day_of_year = s.tm_yday;

	if ((config->syslog != SYSLOG_NONE) && (config->syslog_ident != NULL)) {
		openlog(config->syslog_ident, 0, 0);
	}

	return 0;
}

/* Write a timestamp to a logfile.
 */
static void print_timestamp(char *str) {
	time_t t;
	struct tm s;

	time(&t);
	localtime_r(&t, &s);
	str[TIMESTAMP_SIZE - 1] = '\0';
	strftime(str, TIMESTAMP_SIZE - 1, "%a %d %b %Y %T %z|", &s);
}

/* Keep escape characters out of the logfile
 */
static char *secure_string(char *str) {
	char *c = str;

	if (str != NULL) {
		while (*c != '\0') {
			if (*c == '\27') {
				*c = ' ';
			}
			c++;
		}
	}

	return str;
}

/*---< Main log functions >------------------------------------------*/

/* Log the Hiawatha process ID.
 */
void log_pid(t_config *config, pid_t pid, uid_t server_uid) {
	FILE *fp;

	if ((fp = fopen(config->pidfile, "w")) == NULL) {
		fprintf(stderr, "Warning: can't write PID file %s.\n", config->pidfile);
		return;
	}

	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);

#ifndef CYGWIN
	if (chmod(config->pidfile, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
		fprintf(stderr, "Warning: can't chmod PID file %s. Make sure it's only writable for root!\n", config->pidfile);
	}
	if (server_uid == 0) {
		if (chown(config->pidfile, 0, 0) == -1) {
			fprintf(stderr, "Warning: can't chown PID file %s. Make sure it's owned by root!\n", config->pidfile);
		}
	}
#else
	/* prevent unused warning */
	(void)server_uid;
#endif
}

/* Log a system message
 */
void log_system(t_config *config, char *mesg, ...) {
	FILE *fp;
	va_list args1, args2;
	char str[TIMESTAMP_SIZE];
	char text[256];

	if (mesg == NULL) {
		return;
	}
	
	print_timestamp(str);

	va_start(args1, mesg);
	va_copy(args2, args1);

	if ((fp = fopen(config->system_logfile, "a")) != NULL) {
		fprintf(fp, "0.0.0.0|%s", str);
		vfprintf(fp, mesg, args1);
		fprintf(fp, EOL);
		fclose(fp);
	}

	if ((config->syslog & SYSLOG_SYSTEM) > 0) {
		vsnprintf(text, 255, mesg, args2);
		text[255] = '\0';
		syslog(LOG_INFO, "system|%s%s", str, text);
	}

	va_end(args1);
	va_end(args2);
}

/* Log a system message about a session
 */
void log_system_session(t_session *session, char *mesg, ...) {
	FILE *fp;
	va_list args1, args2;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE + 2];
	char text[256];

	if (mesg == NULL) {
		return;
	}

	va_start(args1, mesg);
	va_copy(args2, args1);

	ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));

	if ((fp = fopen(session->config->system_logfile, "a")) != NULL) {
		fprintf(fp, "%s", str);
		vfprintf(fp, mesg, args1);
		fprintf(fp, EOL);
		fclose(fp);
	}

	if ((session->config->syslog & SYSLOG_SYSTEM) > 0) {
		vsnprintf(text, 255, mesg, args2);
		text[255] = '\0';
		syslog(LOG_INFO, "system|%s%s", str, text);
	}

	va_end(args1);
	va_end(args2);
}

/* Log an error for a specific file
 */
void log_error_file(t_session *session, char *file, char *mesg, ...) {
	FILE *fp;
	va_list args1, args2;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE + 2];
	char text[256];

	if (mesg == NULL) {
		return;
	}

	if (session->host == NULL) {
		if (session->config->first_host->error_logfile == NULL) {
			return;
		}
		fp = fopen(session->config->first_host->error_logfile, "a");
	} else {
		if (session->host->error_logfile == NULL) {
			return;
		}
		fp = fopen(session->host->error_logfile, "a");
	}
	if ((fp == NULL) && ((session->config->syslog & SYSLOG_ERROR) == 0)) {
		return;
	}

	va_start(args1, mesg);
	va_copy(args2, args1);

	if (session->config->anonymize_ip) {
		anonymized_ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	} else {
		ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	}

	strcat(str, "|");
	print_timestamp(str + strlen(str));

	if (fp != NULL) {
		if (file == NULL) {
			fprintf(fp, "%s", str);
		} else {
			fprintf(fp, "%s%s|", str, file);
		}
		vfprintf(fp, mesg, args1);
		fprintf(fp, EOL);
		fclose(fp);
	}

	if ((session->config->syslog & SYSLOG_ERROR) > 0) {
		vsnprintf(text, 255, mesg, args2);
		text[255] = '\0';
		if (file == NULL) {
			syslog(LOG_ERR, "error|%s%s", str, text);
		} else {
			syslog(LOG_ERR, "error|%s%s|%s", str, file, text);
		}
	}

	va_end(args1);
	va_end(args2);
}

/* Log a CGI error.
 */
void log_error_cgi(t_session *session, char *mesg) {
	FILE *fp;
	char *c, str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE];
	int len = 0;

	if (mesg == NULL) {
		return;
	} else if ((session->host->error_logfile == NULL) && ((session->config->syslog & SYSLOG_ERROR) == 0)) {
		return;
	}

	c = mesg;
	while (*c != '\0') {
		if (*c == '\n') {
			if (*(c + 1) == '\0') {
				*c = '\0';
			} else {
				*c = '|';
			}
		} else {
			len++;
		}
		c++;
	}

	if (len == 0) {
		return;
	}

	if (session->config->anonymize_ip) {
		anonymized_ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	} else {
		ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	}

	strcat(str, "|");
	print_timestamp(str + strlen(str));

	if ((fp = fopen(session->host->error_logfile, "a")) != NULL) {
		if (session->file_on_disk == NULL) {
			fprintf(fp, "%s-|%s"EOL, str, secure_string(mesg));
		} else {
			fprintf(fp, "%s%s|%s"EOL, str, session->file_on_disk, secure_string(mesg));
		}
		fclose(fp);
	}

	if ((session->config->syslog & SYSLOG_ERROR) > 0) {
		if (session->file_on_disk == NULL) {
			syslog(LOG_ERR, "error|%s-|%s", str, secure_string(mesg));
		} else {
			syslog(LOG_ERR, "error|%s%s|%s", str, session->file_on_disk, secure_string(mesg));
		}

	}
}

/* Log a HTTP request.
 */
void log_request(t_session *session) {
	char str[BUFFER_SIZE + 1], timestamp[TIMESTAMP_SIZE], ip_address[IP_ADDRESS_SIZE];
	char *user, *uri, *vars, *path_info, *referer, *user_agent;
	t_http_header *http_header;
	int offset;
	time_t t;
	struct tm s;

	if ((session->host->access_logfile == NULL) && ((session->config->syslog & SYSLOG_ACCESS) == 0)) {
		return;
	} else if (ip_allowed(&(session->ip_address), session->config->logfile_mask) == deny) {
		return;
	}

	str[BUFFER_SIZE] = '\0';

#ifdef ENABLE_TOOLKIT
	if (session->request_uri == NULL) {
#endif
		uri = secure_string(session->uri);
		path_info = secure_string(session->path_info);
		vars = secure_string(session->vars);
#ifdef ENABLE_TOOLKIT
	} else {
		uri = secure_string(session->request_uri);
		path_info = NULL;
		vars = NULL;
	}
#endif

	if ((referer = get_referer_header(session->http_headers)) != NULL) {
		referer = secure_string(referer);
	}

	if ((user_agent = get_http_header("User-Agent:", session->http_headers)) != NULL) {
		user_agent = secure_string(user_agent);
	}

	if (session->config->log_format == hiawatha) {
		/* Hiawatha log format
		 */
		if (session->config->anonymize_ip) {
			anonymized_ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
		} else {
			ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
		}

		strcat(str, "|");
		offset = strlen(str);
		print_timestamp(str + offset);
		offset += strlen(str + offset);

		snprintf(str + offset, BUFFER_SIZE - offset, "%d|%lld|%s %s", session->return_code, (long long)session->bytes_sent, secure_string(session->method), uri);
		offset += strlen(str + offset);

		if ((offset < BUFFER_SIZE) && (path_info != NULL)) {
			snprintf(str + offset, BUFFER_SIZE - offset, "/%s", path_info);
			offset += strlen(str + offset);
		}
		if ((offset < BUFFER_SIZE) && (vars != NULL)) {
			snprintf(str + offset, BUFFER_SIZE - offset, "?%s", vars);
			offset += strlen(str + offset);
		}

		if (offset < BUFFER_SIZE) {
			snprintf(str + offset, BUFFER_SIZE - offset, " %s", secure_string(session->http_version));
			offset += strlen(str + offset);
		}

		if (offset < BUFFER_SIZE) {
			if (referer == NULL) {
				referer = "";
			}

			snprintf(str + offset, BUFFER_SIZE - offset, "|%s", referer);
			offset += strlen(str + offset);
		}

		if (offset < BUFFER_SIZE) {
			if (user_agent == NULL) {
				user_agent = "";
			}

			snprintf(str + offset, BUFFER_SIZE - offset, "|%s", user_agent);
			offset += strlen(str + offset);
		}

		if (offset < BUFFER_SIZE) {
			http_header = session->http_headers;
			while (http_header != NULL) {
				if (strncasecmp("Authorization:", http_header->data, 14) == 0) {
					goto next_header;
				}
				if (strncasecmp("Cookie:", http_header->data, 7) == 0) {
					goto next_header;
				}
				if (strncasecmp("Proxy-Authorization:", http_header->data, 20) == 0) {
					goto next_header;
				}

				if ((http_header->data + http_header->value_offset == referer) || (http_header->data + http_header->value_offset == user_agent)) {
					goto next_header;
				}

				snprintf(str + offset, BUFFER_SIZE - offset, "|%s", secure_string(http_header->data));
				if ((offset += strlen(str + offset)) >= BUFFER_SIZE) {
					break;
				}

next_header:
				http_header = http_header->next;
			}
		}
	} else {
		/* Common Log Format
		 */
		if (session->config->anonymize_ip) {
			anonymized_ip_to_str(&(session->ip_address), ip_address, IP_ADDRESS_SIZE);
		} else {
			ip_to_str(&(session->ip_address), ip_address, IP_ADDRESS_SIZE);
		}

		if ((user = session->remote_user) != NULL) {
			user = secure_string(user);
		} else {
			user = "-";
		}

		time(&t);
		localtime_r(&t, &s);
		timestamp[TIMESTAMP_SIZE - 1] = '\0';
		strftime(timestamp, TIMESTAMP_SIZE - 1, "%d/%b/%Y:%T %z", &s);

		snprintf(str, BUFFER_SIZE, "%s - %s [%s] \"%s %s", ip_address, user, timestamp, secure_string(session->method), uri);
		offset = strlen(str);
		if ((offset < BUFFER_SIZE) && (path_info != NULL)) {
			snprintf(str + offset, BUFFER_SIZE - offset, "/%s", path_info);
			offset += strlen(str + offset);
		}
		if ((offset < BUFFER_SIZE) && (vars != NULL)) {
			snprintf(str + offset, BUFFER_SIZE - offset, "?%s", vars);
			offset += strlen(str + offset);
		}
		if (offset < BUFFER_SIZE) {
			snprintf(str + offset, BUFFER_SIZE - offset, " %s\" %d %lld", secure_string(session->http_version), session->return_code, (long long)session->bytes_sent);
		}

		if (session->config->log_format == extended) {
			/* Extended Common Log Format
			 */
			offset += strlen(str + offset);
			if (offset < BUFFER_SIZE) {
				if (referer == NULL) {
					referer = "-";
				}

				snprintf(str + offset, BUFFER_SIZE - offset, " \"%s\"", referer);
				offset += strlen(str + offset);
			}
			if (offset < BUFFER_SIZE) {
				if (user_agent == NULL) {
					user_agent = "-";
				}

				snprintf(str + offset, BUFFER_SIZE - offset, " \"%s\"", user_agent);
				offset += strlen(str + offset);
			}
		}
	}

	pthread_mutex_lock(&accesslog_mutex);

	if ((session->host->access_logfile != NULL) && (*(session->host->access_fp) == NULL)) {
		*(session->host->access_fp) = fopen(session->host->access_logfile, "a");
	}

	if (*(session->host->access_fp) != NULL) {
		if (fprintf(*(session->host->access_fp), "%s"EOL, str) >= 0) {
			fflush(*(session->host->access_fp));
		} else {
			fclose(*(session->host->access_fp));
			session->host->access_fp = NULL;
		}
	}

	pthread_mutex_unlock(&accesslog_mutex);

	if ((session->config->syslog & SYSLOG_ACCESS) > 0) {
		syslog(LOG_INFO, "access|%s", str);
	}
}

#ifdef ENABLE_HTTP2
/* HTTP/2 version of log_garbage()
 */
static char *h2_garbage_record(t_session *session) {
	t_http_header *header;
	const char *method, *uri, *version;
	size_t len;
	char *record, *pos;

	method  = (session->method != NULL) ? session->method : "-";
	uri     = (session->request_uri != NULL) ? session->request_uri : "-";
	version = (session->http_version != NULL) ? session->http_version : "HTTP/2.0";

	len = strlen(method) + strlen(uri) + strlen(version) + 3;
	for (header = session->http_headers; header != NULL; header = header->next) {
		len += (size_t)header->length + 2;
	}

	if ((record = (char*)malloc(len)) == NULL) {
		return NULL;
	}

	pos = record + snprintf(record, len, "%s %s %s", method, uri, version);
	for (header = session->http_headers; header != NULL; header = header->next) {
		*(pos++) = '\r';
		*(pos++) = '\n';
		memcpy(pos, header->data, (size_t)header->length);
		pos += header->length;
	}
	*pos = '\0';

	return record;
}
#endif


/* Log garbage sent by a client.
 */
void log_garbage(t_session *session) {
	int i, spaces = 2;
	FILE *fp;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE], *record;
#ifdef ENABLE_HTTP2
	char *h2_record = NULL;
#endif

	if ((session->config->garbage_logfile == NULL) && ((session->config->syslog & SYSLOG_GARBAGE) == 0)) {
		return;
	}

	if (session->request != NULL) {
		for (i = 0; i < session->bytes_in_buffer; i++) {
			if (session->request[i] == '\0') {
				if (spaces > 0) {
					session->request[i] = ' ';
					spaces--;
				} else {
					session->request[i] = '\r';
				}
			}
		}

		record = session->request;
#ifdef ENABLE_HTTP2
	} else if (session->is_http2) {
		if ((h2_record = h2_garbage_record(session)) == NULL) {
			return;
		}

		record = h2_record;
#endif
	} else {
		return;
	}

	ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));

	if (session->config->garbage_logfile != NULL) {
		if ((fp = fopen(session->config->garbage_logfile, "a")) != NULL) {
			fprintf(fp, "%s%s"EOL, str, record);
			fclose(fp);
		}
	}

	if ((session->config->syslog & SYSLOG_GARBAGE) > 0) {
		syslog(LOG_INFO, "garbage|%s%s", str, record);
	}

#ifdef ENABLE_HTTP2
	check_free(h2_record);
#endif
}

/* Log exploit attempt
 */
void log_exploit_attempt(t_session *session, char *type, char *data) {
	FILE *fp;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE], *host, *uri, *unknown = "<unknown>";

	if (type == NULL) {
		return;
	} else if ((session->config->exploit_logfile == NULL) && ((session->config->syslog & SYSLOG_EXPLOIT) == 0)) {
		return;
	}
	
	host = (session->host->hostname.size > 0) ? session->host->hostname.item[0] : unknown;
	uri = (session->request_uri != NULL) ? session->request_uri : unknown;

	ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));

	if (session->config->exploit_logfile != NULL) {
		if ((fp = fopen(session->config->exploit_logfile, "a")) == NULL) {
			return;
		}
		if (data == NULL) {
			fprintf(fp, "%s%s|%s|%s"EOL, str, host, uri, type);
		} else {
			fprintf(fp, "%s%s|%s|%s|%s"EOL, str, host, uri, type, data);
		}
		fclose(fp);
	}

	if ((session->config->syslog & SYSLOG_EXPLOIT) > 0) {
		if (data == NULL) {
			syslog(LOG_WARNING, "exploit|%s%s|%s|%s", str, host, uri, type);
		} else {
			syslog(LOG_WARNING, "exploit|%s%s|%s|%s|%s", str, host, uri, type, data);
		}
	}
}

/* Log an unbanning.
 */
void log_unban(t_config *config, t_ip_addr *ip_address, unsigned long connect_attempts) {
	FILE *fp;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE];

	if (ip_address == NULL) {
		return;
	}
	
	ip_to_str(ip_address, str, IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));

	if ((fp = fopen(config->system_logfile, "a")) != NULL) {
		fprintf(fp, "%sUnbanned (%lu connect attempts during ban)"EOL, str, connect_attempts);
		fclose(fp);
	}

	if ((config->syslog & SYSLOG_SYSTEM) > 0) {
		syslog(LOG_INFO, "system|%sUnbanned (%lu connect attempts during ban)", str, connect_attempts);
	}
}

/* Close open access logfiles.
 */
void close_logfiles(t_host *host, time_t now) {
	pthread_mutex_lock(&accesslog_mutex);

	while (host != NULL) {
		if ((now >= host->access_time + LOGFILE_OPEN_TIME) || (now == 0)) {
			if (*(host->access_fp) != NULL) {
				fclose(*(host->access_fp));
				*(host->access_fp) = NULL;
			}
		}
		host = host->next;
	}

	pthread_mutex_unlock(&accesslog_mutex);
}

/* Close all open logfile descriptors
 */
void close_logfiles_for_cgi_run(t_host *host) {
	while (host != NULL) {
		if (*(host->access_fp) != NULL) {
			fclose(*(host->access_fp));
		}
		host = host->next;
	}
}

/* Compress logfile
 */
static int gzip_logfile(char *file) {
	char *gz_file = NULL, buffer[GZIP_BUFFER_SIZE];
	int result = -1, fd_in = -1, fd_out = -1;
	int bytes_read, bytes_written, total_written;
	struct stat stat_in;
	gzFile gzhandle = NULL;
	size_t len;

	/* Input file
	 */
	if ((fd_in = open(file, O_RDONLY)) == -1) {
		goto gzip_fail;
	}

	if (fstat(fd_in, &stat_in) == -1) {
		goto gzip_fail;
	}

	/* Output file
	 */
	len = strlen(file) + 4;
	if ((gz_file = (char*)malloc(len)) == NULL) {
		goto gzip_fail;
	}
	snprintf(gz_file, len, "%s.gz", file);

	if ((fd_out = open(gz_file, O_CREAT | O_WRONLY, stat_in.st_mode)) == -1) {
		goto gzip_fail;
	}

	if ((gzhandle = gzdopen(fd_out, "w6")) == NULL) {
		goto gzip_fail;
	}

	/* Compress file
	 */
	while ((bytes_read = read(fd_in, buffer, GZIP_BUFFER_SIZE)) != 0) {
		if (bytes_read == -1) {
			if (errno != EAGAIN) {
				goto gzip_fail;
			}
			continue;
		}

		total_written = 0;
		while (total_written < bytes_read) {
			if ((bytes_written = gzwrite(gzhandle, buffer + total_written, bytes_read - total_written)) == -1) {
				goto gzip_fail;
			}
			total_written += bytes_written;
		}
	}

	result = 0;

gzip_fail:
	if (gzhandle != NULL) {
		gzclose(gzhandle);
	}

	if (fd_out != -1) {
		close(fd_out);
		if (result == -1) {
			unlink(gz_file);
		}
	}

	if (fd_in != -1) {
		close(fd_in);
	}

	if (result == 0) {
		if (unlink(file) == -1) {
			unlink(gz_file);
		}
	}

	if (gz_file != NULL) {
		free(gz_file);
	}

	return result;
}

/* Rotate logfile
 */
static int rotate_access_logfile(t_host *host, char *timestamp) {
	int fd;
	char *logfile, *dot;
	size_t len, prefix;

	len = strlen(host->access_logfile) + strlen(timestamp) + 2;
	if ((logfile = (char*)malloc(len)) == NULL) {
		return -1;
	}

	if ((dot = strrchr(host->access_logfile, '.')) != NULL) {
		prefix = dot - host->access_logfile;
		memcpy(logfile, host->access_logfile, prefix);
		snprintf(logfile + prefix, len - prefix, "-%s%s", timestamp, dot);
	} else {
		snprintf(logfile, len, "%s-%s", host->access_logfile, timestamp);
	}

	if (rename(host->access_logfile, logfile) == -1) {
		free(logfile);
		return -1;
	}

	if ((fd = open(host->access_logfile, O_CREAT, LOG_PERM)) == -1) {
		rename(logfile, host->access_logfile);
		free(logfile);
		return -1;
	}
	close(fd);

	gzip_logfile(logfile);

	free(logfile);

	return 0;
}

/* Rotate logfiles
 */
void rotate_access_logfiles(t_config *config, time_t now) {
	struct tm s;
	char timestamp[16];
	t_host *host;
	int result;

	localtime_r(&now, &s);
	if (s.tm_yday == day_of_year) {
		return;
	}
	day_of_year = s.tm_yday;

	strftime(timestamp, 15, "%Y-%m-%d", &s);

	host = config->first_host;
	while (host != NULL) {
		if (host->access_logfile == NULL) {
			result = 0;
		} else if (host->rotate_access_log == daily) {
			result = rotate_access_logfile(host, timestamp);
		} else if ((host->rotate_access_log == weekly) && (s.tm_wday == 1)) {
			result = rotate_access_logfile(host, timestamp);
		} else if ((host->rotate_access_log == monthly) && (s.tm_mday == 1)) {
			result = rotate_access_logfile(host, timestamp);
		} else {
			result = 0;
		}

		if (result == -1) {
			log_system(config, "Error rotating %s", host->access_logfile);
		}

		host = host->next;
	}
}

#ifdef ENABLE_DEBUG
/* Log debug information
 */
void log_debug(t_session *session, char *mesg, ...) {
	FILE *fp;
	va_list args;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE];

	if (mesg == NULL) {
		return;
	} else if ((fp = fopen(LOG_DIR"/access.log", "a")) == NULL) {
		return;
	}

	va_start(args, mesg);

	ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));
	fprintf(fp, "%s%05d|", str, session->thread_id);
	vfprintf(fp, mesg, args);
	fprintf(fp, EOL);
	fclose(fp);

	va_end(args);
}

/* Log a text.
 */
void log_string(char *logfile, char *mesg, ...) {
	FILE *fp;
	va_list args;
	char str[TIMESTAMP_SIZE];

	if ((logfile == NULL) || (mesg == NULL)) {
		return;
	} else if ((fp = fopen(logfile, "a")) == NULL) {
		return;
	}

	va_start(args, mesg);

	print_timestamp(str);
	fprintf(fp, "%s", str);
	vfprintf(fp, mesg, args);
	fprintf(fp, EOL);
	fclose(fp);

	va_end(args);
}
#endif
