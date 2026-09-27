#include "config.h"

#ifdef ENABLE_MEMDBG

#define MAXIMUM_LINES  10
#define CHARS_PER_LINE 16

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

typedef struct type_alloc_log {
	void         *ptr;
	size_t       size;
	char         *alloc_filename;
	unsigned int alloc_line_nr;
	unsigned int freed;
	char         *free_filename;
	unsigned int free_line_nr;
	pthread_t    pthread_id;

	struct type_alloc_log *next;
} t_alloc_log;

static t_alloc_log *alloc_log = NULL;
static pthread_mutex_t alloc_log_mutex;

/* Initialize memory debug module
 */
int init_memdbg(void) {
	if (pthread_mutex_init(&alloc_log_mutex, NULL) != 0) {
		return -1;
	}

	fprintf(stderr, "MemDbg module activated.\n");

	return 0;
}

/* Static find log
 */
static t_alloc_log *find_log(void *ptr) {
	t_alloc_log *log;

	pthread_mutex_lock(&alloc_log_mutex);

	log = alloc_log;
	while (log != NULL) {
		if (log->ptr == ptr) {
			break;
		}
		log = log->next;
	}

	pthread_mutex_unlock(&alloc_log_mutex);

	return log;
}

/* Set log
 */
static void set_log(t_alloc_log *log, void *ptr, size_t size, char *filename, int line_nr) {
	log->ptr = ptr;
	log->size = size;
	log->alloc_filename = strdup(filename);
	log->alloc_line_nr = line_nr;
	log->freed = false;
	log->free_filename = NULL;
	log->free_line_nr = 0;
	log->pthread_id = pthread_self();
}

/* Log memory allocation
 */
static void log_alloc(void *ptr, size_t size, char *filename, int line_nr) {
	t_alloc_log *log;

	if ((log = malloc(sizeof(t_alloc_log))) == NULL) {
		return;
	}

	set_log(log, ptr, size, filename, line_nr);

	pthread_mutex_lock(&alloc_log_mutex);

	log->next = alloc_log;
	alloc_log = log;

	pthread_mutex_unlock(&alloc_log_mutex);
}

/* Report unallocated memory
 */
static void report_unallocated_memory(t_alloc_log *log, char *action, char *filename, int line_nr) {
	fprintf(stderr, "%s unallocated memory at %s line %d\n", action, filename, line_nr);
	fprintf(stderr, "  allocated by %s line %d\n", log->alloc_filename, log->alloc_line_nr);
	if (log->free_filename != NULL) {
		fprintf(stderr, "  freed by %s line %d\n", log->free_filename, log->free_line_nr);
	}
}

/* Log freeing of memory
 */
static int log_free(void *ptr, char *filename, int line_nr) {
	t_alloc_log *log;
	int result = 0;

	if ((log = find_log(ptr)) != NULL) {
		if (log->freed == false) {
			log->free_filename = strdup(filename);
			log->free_line_nr = line_nr;
			log->freed = true;
		} else {
			report_unallocated_memory(log, "Freeing", filename, line_nr);
			result = -1;
		}
	}

	return result;
}

/* Clear memory allocation log
 */
void memdbg_clear_log(void) {
	t_alloc_log *log;

	pthread_mutex_lock(&alloc_log_mutex);

	while (alloc_log != NULL) {
		log = alloc_log;
		alloc_log = alloc_log->next;

		if (log->alloc_filename != NULL) {
			free(log->alloc_filename);
		}
		if (log->free_filename != NULL) {
			free(log->free_filename);
		}
		free(log);
	}

	pthread_mutex_unlock(&alloc_log_mutex);
}

/* Allocate memory
 */
void *memdbg_malloc(size_t size, char *filename, int line_nr) {
	void *result;

	if ((result = malloc(size)) != NULL) {
		log_alloc(result, size, filename, line_nr);
	}

	return result;
}

/* Re-allocate memory
 */
void *memdbg_realloc(void *ptr, size_t size, char *filename, int line_nr) {
	void *result;
	t_alloc_log *log = NULL;

	if (ptr != NULL) {
		if ((log = find_log(ptr)) == NULL) {
			report_unallocated_memory(log, "Re-allocating", filename, line_nr);
		} else if (log->freed) {
			report_unallocated_memory(log, "Re-allocating", filename, line_nr);
		}
	}

	if ((result = realloc(ptr, size)) != NULL) {
		if (log == NULL) {
			log_alloc(result, size, filename, line_nr);
		} else {
			pthread_mutex_lock(&alloc_log_mutex);

			if (log->alloc_filename != NULL) {
				free(log->alloc_filename);
			}
			if (log->free_filename != NULL) {
				free(log->free_filename);
			}

			set_log(log, result, size, filename, line_nr);

			pthread_mutex_unlock(&alloc_log_mutex);
		}
	}

	return result;
}

/* Allocate multiple memory blocks
 */
void *memdbg_calloc(size_t nmemb, size_t size, char *filename, int line_nr) {
	void *result;

	if ((result = calloc(nmemb, size)) != NULL) {
		log_alloc(result, nmemb * size, filename, line_nr);
	}

	return result;
}

/* Re-allocate multiple memory blocks
 */
void *memdbg_reallocarray(void *ptr, size_t nmemb, size_t size, char *filename, int line_nr) {
	void *result;
	t_alloc_log *log = NULL;

	if (ptr != NULL) {
		if ((log = find_log(ptr)) == NULL) {
			report_unallocated_memory(log, "Re-allocating", filename, line_nr);
		} else if (log->freed) {
			report_unallocated_memory(log, "Re-allocating", filename, line_nr);
		}
	}

	if ((result = reallocarray(ptr, nmemb, size)) != NULL) {
		if (log == NULL) {
			log_alloc(result, nmemb * size, filename, line_nr);
		} else {
			pthread_mutex_lock(&alloc_log_mutex);

			if (log->alloc_filename != NULL) {
				free(log->alloc_filename);
			}
			if (log->free_filename != NULL) {
				free(log->free_filename);
			}

			set_log(log, result, nmemb * size, filename, line_nr);

			pthread_mutex_unlock(&alloc_log_mutex);
		}
	}

	return result;
}

/* Duplicate string
 */
char *memdbg_strdup(const char *str, char *filename, int line_nr) {
	char *result;

	if ((result = strdup(str)) != NULL) {
		log_alloc(result, strlen(result), filename, line_nr);
	}

	return result;
}

/* Duplicate some bytes of string
 */
char *memdbg_strndup(const char *str, size_t size, char *filename, int line_nr) {
	char *result;

	if ((result = strndup(str, size)) != NULL) {
		log_alloc(result, size, filename, line_nr);
	}

	return result;
}

/* Free memory
 */
void memdbg_free(void *ptr, char *filename, int line_nr) {
	if (ptr == NULL) {
		return;
	}

	if (log_free(ptr, filename, line_nr) == 0) {
		free(ptr);
	}
}

/* Print memory allocations
 */
void memdbg_print_log(bool print_all) {
	t_alloc_log *log;
	pthread_t self;
	unsigned char c;
	size_t line, i, max_line, max_i, total = 0;

	self = pthread_self();

	pthread_mutex_lock(&alloc_log_mutex);

	fprintf(stderr, "--[ %c ]--------------------------\n", print_all ? 'A' : 'T');

	log = alloc_log;
	while (log != NULL) {
		if (log->freed) {
			log = log->next;
			continue;
		}

		if (print_all) {
			total += log->size;
		} else if (pthread_equal(log->pthread_id, self) == 0) {
			log = log->next;
			continue;
		}

		if (log->alloc_filename != NULL) {
			fprintf(stderr, "Filename:    %s\n", log->alloc_filename);
		}
		fprintf(stderr, "Line number: %d\n", log->alloc_line_nr);
		fprintf(stderr, "Memory size: %ld\n", (long)log->size);

		if ((max_line = log->size) > MAXIMUM_LINES * CHARS_PER_LINE) {
			max_line = MAXIMUM_LINES * CHARS_PER_LINE;
		}
		for (line = 0; line < max_line; line += CHARS_PER_LINE) {
			if ((max_i = log->size - line) > CHARS_PER_LINE) {
				max_i = CHARS_PER_LINE;
			}

			for (i = 0; i < max_i; i++) {
				fprintf(stderr, "%02X ", *((unsigned char*)log->ptr + line + i));
			}
			for (i = max_i; i < CHARS_PER_LINE; i++) {
				fprintf(stderr, "   ");
			}

			fprintf(stderr, "  |");
			for (i = 0; i < max_i; i++) {
				c = *((unsigned char*)log->ptr + line + i);
				if ((c >= 32) && (c <= 126)) {
					fprintf(stderr, "%c", c);
				} else {
					fprintf(stderr, ".");
				}
			}
			for (i = max_i; i < CHARS_PER_LINE; i++) {
				fprintf(stderr, " ");
			}

			fprintf(stderr, "|\n");
		}

		fprintf(stderr, "\n");

		log = log->next;
	}

	if (print_all) {
		fprintf(stderr, "Total memory usage: %ld\n\n", (long)total);
	}

	pthread_mutex_unlock(&alloc_log_mutex);
}

#endif
