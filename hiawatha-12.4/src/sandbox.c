/* sandbox.c -- OS-level sandboxing for Hiawatha
 *
 * Defense-in-depth philosophy: sandbox errors are never fatal.
 * If a syscall fails (old kernel, missing support), we log and continue.
 * The application always runs. Sandboxing is an additional protection layer.
 *
 * Platforms:
 *   OpenBSD: pledge(2) + unveil(2)
 *   Linux:   Landlock + seccomp-bpf
 *   macOS:   Seatbelt (sandbox-exec re-exec)
 *   Other:   No-op with log warning
 */

#include "config.h"

#ifdef ENABLE_SANDBOX

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "libstr.h"
#include "alternative.h"
#include "sandbox.h"
#include "serverconfig.h"
#include "memdbg.h"

// Maximum number of paths we track for sandboxing (room for many virtual hosts
// plus their auth/listing/backend/exec/TLS paths; overflow drops silently, see
// sandbox_add_path). Sizing: a fully-configured virtual host uses ~10-14 entries
// (docroot, access+error logfile, a log-rotation parent dir, password+group file,
// ShowIndex + ErrorXSLT stylesheets, TLS key/cert/CA/CRL), plus one entry per
// Alias/ScriptAlias target and per exec'd program (CGI/RunOn*). sandbox_add_path
// coalesces paths shared between hosts (shared docroot, cert, password file), so
// real counts are usually lower. Add a dozen globals. An entry costs 16 bytes
// (2048 = 32 KB). Tune to the deployment: 512 or 1024 suffices for small/embedded
// systems, 4096 gives headroom for a couple hundred feature-rich virtual hosts.
#define SANDBOX_MAX_PATHS 2048

typedef struct {
	const char *path;
	char perms[8]; // union of the "r"/"w"/"c"/"x" chars for this path, NUL-terminated
} t_sandbox_path;

static t_sandbox_path sandbox_paths[SANDBOX_MAX_PATHS];
static int sandbox_path_count = 0;

/* Set by sandbox_collect_paths() from the running config; consumed by the
 * OpenBSD pledge promise string. exec = the server execs a program (CGI,
 * RunOnDownload, RunOnAlter); unix = a backend is reached over an AF_UNIX
 * socket (FastCGI/reverse proxy/WebSocket). */
static bool sandbox_need_exec = false;
static bool sandbox_need_unix = false;
/* True if any CGI is run through the (setuid) cgi-wrapper. On OpenBSD this
 * disables execpromises: pledge(2) blocks execve of a setuid/setgid target with
 * EACCES once execpromises is set, so a wrapped CGI would fail to launch. Those
 * setups rely on the wrapper's own chroot for confinement instead. */
static bool sandbox_need_wrap = false;

static void sandbox_add_path(const char *path, const char *perms) {
	int i;
	const char *p;
	size_t n;

	if ((path == NULL) || (perms == NULL)) {
		return;
	}

	/* Coalesce by path: if this path was already collected, merge (union) any
	 * new permission characters into the existing entry instead of storing a
	 * second entry. Many bindings/hosts share the same certificate, logfile or
	 * document root; one entry per path avoids wasting sandbox_paths[] slots and
	 * cluttering the profile. Crucially on OpenBSD it also prevents a later
	 * unveil() with weaker perms from REPLACING an earlier stronger one — unveil
	 * is last-wins per path, not a union — so e.g. a document root shared by a
	 * CGI host ("rx") and a non-CGI host ("r") correctly ends up "rx". */
	for (i = 0; i < sandbox_path_count; i++) {
		if (strcmp(sandbox_paths[i].path, path) == 0) {
			n = strlen(sandbox_paths[i].perms);
			for (p = perms; *p != '\0'; p++) {
				if ((strchr(sandbox_paths[i].perms, *p) == NULL) &&
				    (n + 1 < sizeof(sandbox_paths[i].perms))) {
					sandbox_paths[i].perms[n++] = *p;
					sandbox_paths[i].perms[n] = '\0';
				}
			}
			return;
		}
	}

	if (sandbox_path_count >= SANDBOX_MAX_PATHS) {
		fprintf(stderr, "Sandbox: too many paths (max %d), skipping %s\n", SANDBOX_MAX_PATHS, path);
		return;
	}

	sandbox_paths[sandbox_path_count].path = path;
	strlcpy(sandbox_paths[sandbox_path_count].perms, perms, sizeof(sandbox_paths[sandbox_path_count].perms));
	sandbox_path_count++;
}

/* Grant the parent directory of a file. Needed for the pre-exec chdir into a
 * program's directory (RunOnDownload/RunOnAlter on OpenBSD) and for log rotation,
 * which renames the live log onto a sibling in the same directory. The dirname
 * copy is intentionally not freed: sandbox_add_path stores the pointer, and the
 * paths live for the whole process lifetime. */
static void sandbox_add_parent_dir(const char *path, const char *perms) {
	char *dir, *slash;

	if (path == NULL) {
		return;
	}
	if ((dir = strdup(path)) == NULL) {
		return;
	}
	slash = strrchr(dir, '/');
	if (slash == dir) {
		dir[1] = '\0';	// path directly under root: parent is "/"
	} else if (slash != NULL) {
		*slash = '\0';
	} else {
		free(dir);	// relative path, no directory component to grant
		return;
	}
	sandbox_add_path(dir, perms);
}

/* True if any configured feature makes the server exec() a program in-process:
 * a classifiable CGI request (CGIextension or CGIhandler) that is also enabled
 * (ExecuteCGI, per host or per <Directory>), or a RunOnDownload / RunOnAlter
 * program. FastCGI never execs (it connects to a socket), so a UseFastCGI- or
 * WebDAVapp-forced execute_cgi is filtered out by the classifiable AND-gate. */
static bool sandbox_needs_exec(t_config *config) {
	t_host *host;
	t_directory *dir;
	bool cgi_classifiable, cgi_enabled = false;

	cgi_classifiable = (config->cgi_extension.size > 0) || (config->cgi_handler != NULL);
	for (host = config->first_host; host != NULL; host = host->next) {
		if (host->execute_cgi) {
			cgi_enabled = true;
		}
	}
	for (dir = config->directory; dir != NULL; dir = dir->next) {
		if (dir->execute_cgi_set && dir->execute_cgi) {
			cgi_enabled = true;
		}
	}
	if (cgi_classifiable && cgi_enabled) {
		return true;
	}

	for (dir = config->directory; dir != NULL; dir = dir->next) {
		if (dir->run_on_download != NULL) {
			return true;
		}
	}
	for (host = config->first_host; host != NULL; host = host->next) {
		if (host->run_on_alter != NULL) {
			return true;
		}
	}

	return false;
}

/* True if any host or <Directory> runs its CGI through the cgi-wrapper
 * (WrapCGI). Used on OpenBSD to decide whether execpromises is safe, and by
 * sandbox_check_config() on Linux to reject WrapCGI (NO_NEW_PRIVS defeats the
 * setuid wrapper). */
static bool sandbox_uses_wrap_cgi(t_config *config) {
	t_host *host;
	t_directory *dir;

	for (host = config->first_host; host != NULL; host = host->next) {
		if (host->wrap_cgi != NULL) {
			return true;
		}
	}
	for (dir = config->directory; dir != NULL; dir = dir->next) {
		if (dir->wrap_cgi != NULL) {
			return true;
		}
	}

	return false;
}

/* True if any backend is reached over an AF_UNIX socket (FastCGI, reverse
 * proxy, or WebSocket configured with a filesystem socket path). */
static bool sandbox_needs_unix(t_config *config) {
	t_fcgi_server *fcgi;
	t_host *host;
	t_connect_to *ct, *head;
	t_websocket *ws;
#ifdef ENABLE_RPROXY
	t_rproxy *rp;
#endif

	/* connect_to lists are made circular by check_configuration() (which runs
	 * before collect), so walk each with a head guard. */
	for (fcgi = config->fcgi_server; fcgi != NULL; fcgi = fcgi->next) {
		ct = fcgi->connect_to;
		if (ct == NULL) {
			continue;
		}
		head = ct;
		do {
			if (ct->unix_socket != NULL) {
				return true;
			}
			ct = ct->next;
		} while ((ct != NULL) && (ct != head));
	}
	for (host = config->first_host; host != NULL; host = host->next) {
#ifdef ENABLE_RPROXY
		for (rp = host->rproxy; rp != NULL; rp = rp->next) {
			if (rp->unix_socket != NULL) {
				return true;
			}
		}
#endif
		for (ws = host->websockets; ws != NULL; ws = ws->next) {
			if (ws->unix_socket != NULL) {
				return true;
			}
		}
	}

	return false;
}

/* Programs the server execs live outside website_root (cgi-wrapper, CGIhandler
 * interpreters, RunOnDownload/RunOnAlter). unveil (OpenBSD) and Landlock (Linux)
 * must grant execute on their paths — the pledge "exec" promise alone is not
 * enough without an unveiled path. */
static void sandbox_collect_exec_paths(t_config *config) {
	t_cgi_handler *ch;
	t_directory *dir;
	t_host *host;

	if (sandbox_need_exec == false) {
		return;
	}

	sandbox_add_path(config->cgi_wrapper, "rx");
	for (ch = config->cgi_handler; ch != NULL; ch = ch->next) {
		sandbox_add_path(ch->handler, "rx");
	}
	/* run_program() chdir()s into the program's directory before exec (workers.c),
	 * so the containing directory must be visible too, not just the binary — on
	 * OpenBSD an unveiled file alone is not enough for the chdir to succeed. */
	for (dir = config->directory; dir != NULL; dir = dir->next) {
		sandbox_add_path(dir->run_on_download, "rx");
		sandbox_add_parent_dir(dir->run_on_download, "r");
	}
	for (host = config->first_host; host != NULL; host = host->next) {
		sandbox_add_path(host->run_on_alter, "rx");
		sandbox_add_parent_dir(host->run_on_alter, "r");
	}
}

/* Backend AF_UNIX socket paths need to be exposed for connect() under OpenBSD
 * unveil. Linux Landlock/seccomp do not mediate pathname AF_UNIX sockets, so
 * these entries are a harmless no-op there. connect_to lists are circular
 * (see sandbox_needs_unix), so guard against the cycle. */
static void sandbox_collect_unix_paths(t_config *config) {
	t_fcgi_server *fcgi;
	t_host *host;
	t_connect_to *ct, *head;
	t_websocket *ws;
#ifdef ENABLE_RPROXY
	t_rproxy *rp;
#endif

	if (sandbox_need_unix == false) {
		return;
	}

	for (fcgi = config->fcgi_server; fcgi != NULL; fcgi = fcgi->next) {
		ct = fcgi->connect_to;
		if (ct == NULL) {
			continue;
		}
		head = ct;
		do {
			sandbox_add_path(ct->unix_socket, "rw");
			ct = ct->next;
		} while ((ct != NULL) && (ct != head));
	}
	for (host = config->first_host; host != NULL; host = host->next) {
#ifdef ENABLE_RPROXY
		for (rp = host->rproxy; rp != NULL; rp = rp->next) {
			sandbox_add_path(rp->unix_socket, "rw");
		}
#endif
		for (ws = host->websockets; ws != NULL; ws = ws->next) {
			sandbox_add_path(ws->unix_socket, "rw");
		}
	}
}

/* CGI can be enabled at host level (ExecuteCGI in the host block) or by a
 * <Directory> block the host attaches via UseDirectory — at request time
 * copy_directory_settings() overrides the host flag with the directory's.
 * The document root needs execute permission in both cases, otherwise
 * Directory-only CGI works without the sandbox but fails (500) under it. */
static bool host_runs_cgi(t_host *host) {
	int i;

	if (host->execute_cgi) {
		return true;
	}
	if (host->directory != NULL) {
		for (i = 0; host->directory[i] != NULL; i++) {
			if (host->directory[i]->execute_cgi_set && host->directory[i]->execute_cgi) {
				return true;
			}
		}
	}

	return false;
}

/* A host permits PUT/DELETE (writes into its document tree) when AlterList is
 * set at the host level or on any <Directory> it attaches — copy_directory_settings()
 * can turn Alter on per request. When it can, the document root must be granted
 * write+create, not just read, or every PUT/DELETE fails 403 under the sandbox. */
static bool host_allows_alter(t_host *host) {
	int i;

	if (host->alter_list != NULL) {
		return true;
	}
	if (host->directory != NULL) {
		for (i = 0; host->directory[i] != NULL; i++) {
			if (host->directory[i]->alter_list != NULL) {
				return true;
			}
		}
	}

	return false;
}

int sandbox_collect_paths(t_config *config) {
	t_host *host;
	t_directory *dir;
	t_keyvalue *alias;
	bool cgi;

	sandbox_path_count = 0;

	sandbox_need_exec = sandbox_needs_exec(config);
	sandbox_need_unix = sandbox_needs_unix(config);
	sandbox_need_wrap = sandbox_uses_wrap_cgi(config);

	/* Log files are opened at runtime with O_CREAT|O_APPEND (fopen "a"). On
	 * OpenBSD that requires the unveil "c" (create) permission even when the file
	 * already exists; plain "rw" returns EACCES and silently disables logging
	 * under the sandbox. So logfiles and the runtime work directories get "rwc".
	 * The PID file is different: it is written before the sandbox is applied
	 * (log_pid() at daemonize time) and is never created or removed under the
	 * sandbox, so "rw" suffices and avoids granting create on its parent dir. */
	// Global paths
	sandbox_add_path(config->system_logfile, "rwc");
	sandbox_add_path(config->garbage_logfile, "rwc");
	sandbox_add_path(config->exploit_logfile, "rwc");
	sandbox_add_path(config->work_directory, "rwc");
	sandbox_add_path(config->upload_directory, "rwc");
	sandbox_add_path(config->gzipped_directory, "rwc");
	sandbox_add_path(config->pidfile, "rw");

#ifdef ENABLE_MONITOR
	/* The Monitor host collects stats files under monitor_directory and unlink()s
	 * each after serving it (workers.c) — that needs write+create there, not just
	 * the read the monitor host's website_root grant would give. */
	if (config->monitor_enabled) {
		sandbox_add_path(config->monitor_directory, "rwc");
	}
#endif

	// Per-host paths
	host = config->first_host;
	while (host != NULL) {
		cgi = host_runs_cgi(host);

		/* Document root: read (+exec for CGI); write+create when AlterList lets
		 * clients PUT/DELETE into the tree, else those writes fail 403 (target.c). */
		if (host_allows_alter(host)) {
			sandbox_add_path(host->website_root, cgi ? "rwcx" : "rwc");
		} else {
			sandbox_add_path(host->website_root, cgi ? "rx" : "r");
		}
		sandbox_add_path(host->access_logfile, "rwc");	// "c": opened O_CREAT (see note above)
		sandbox_add_path(host->error_logfile, "rwc");

		/* PasswordFile / group file are read per request during authentication;
		 * an absolute path lies outside website_root and needs its own grant. */
		sandbox_add_path(host->passwordfile, "r");
		sandbox_add_path(host->groupfile, "r");

		/* Alias / ScriptAlias map URLs to paths outside website_root; the target is
		 * stat'd, opened and (ScriptAlias) exec'd per request (http.c/target.c). */
		for (alias = host->alias; alias != NULL; alias = alias->next) {
			sandbox_add_path(alias->value, cgi ? "rx" : "r");
		}
		for (alias = host->script_alias; alias != NULL; alias = alias->next) {
			sandbox_add_path(alias->value, "rx");
		}

#ifdef ENABLE_XSLT
		/* ShowIndex stylesheet and ErrorXSLTfile are opened per request. The
		 * default ShowIndex lives in the config dir, outside website_root; without
		 * this grant the open() fails under the sandbox and the listing falls back
		 * to the raw built-in output. "xml" opens no file. */
		if ((host->show_index != NULL) && (strcmp(host->show_index, "xml") != 0)) {
			sandbox_add_path(host->show_index, "r");
		}
		sandbox_add_path(host->error_xslt_file, "r");
#endif

		/* Access-log rotation renames the live log onto a fresh timestamped sibling
		 * in the same directory, which needs create/remove on the parent directory
		 * (OpenBSD unveil / macOS seatbelt; on Linux the logfile's own "rwc" already
		 * grants its parent dir). */
		if (host->rotate_access_log != never) {
			sandbox_add_parent_dir(host->access_logfile, "rwc");
		}

		host = host->next;
	}

	/* Per-<Directory> auth and listing files may differ from the host's. */
	for (dir = config->directory; dir != NULL; dir = dir->next) {
		sandbox_add_path(dir->passwordfile, "r");
		sandbox_add_path(dir->groupfile, "r");
#ifdef ENABLE_XSLT
		if (dir->show_index_set && (dir->show_index != NULL) &&
		    (strcmp(dir->show_index, "xml") != 0)) {
			sandbox_add_path(dir->show_index, "r");
		}
#endif
	}

	// System paths needed at runtime
	sandbox_add_path("/etc/ssl/certs", "r");
	sandbox_add_path("/dev/urandom", "r");
	sandbox_add_path("/dev/null", "rw");

	// Programs the server execs, and backend UNIX-socket paths
	sandbox_collect_exec_paths(config);
	sandbox_collect_unix_paths(config);

#ifdef ENABLE_TLS
	/* TLS key/cert/CA/CRL files are read at startup. On macOS the sandbox is
	 * applied before that (via the pre-bind re-exec), so they must be readable;
	 * on OpenBSD/Linux the sandbox is applied after they are loaded, so adding
	 * them read-only here is harmless. */
	{
		t_binding *binding;
		t_host *tls_host;

		for (binding = config->binding; binding != NULL; binding = binding->next) {
			sandbox_add_path(binding->key_cert_file, "r");
			sandbox_add_path(binding->ca_cert_file, "r");
			sandbox_add_path(binding->ca_crl_file, "r");
		}
		for (tls_host = config->first_host; tls_host != NULL; tls_host = tls_host->next) {
			sandbox_add_path(tls_host->key_cert_file, "r");
			sandbox_add_path(tls_host->ca_cert_file, "r");
			sandbox_add_path(tls_host->ca_crl_file, "r");
		}
		sandbox_add_path(config->ca_cert_files, "r");
	}
#endif

#ifdef __OpenBSD__
    /* OpenBSD 7.9+: pledge no longer grants implicit open() access
     * to special paths — they must be explicitly unveiled.
     */
    sandbox_add_path("/etc/localtime", "r");
    sandbox_add_path("/usr/share/zoneinfo", "r");
    sandbox_add_path("/etc/resolv.conf", "r");
    sandbox_add_path("/etc/hosts", "r");
    sandbox_add_path("/etc/services", "r");
    sandbox_add_path("/etc/protocols", "r");

    /* CGI runtime paths. When execpromises keeps an exec'd CGI pledged (see
     * sandbox_execpromises), the CGI also inherits the unveil view — so the
     * interpreter, its shared libraries, the dynamic linker AND its data/module
     * trees must be visible, or the CGI cannot run (e.g. perl needs both
     * /usr/lib/libperl.so and its modules under /usr/libdata/perl5; php/python
     * have their own trees). Enumerating each interpreter's dirs is fragile, so
     * grant read+execute on the system trees /usr, /bin, /sbin as a group. This
     * stays far tighter than the pre-sandbox state (the whole filesystem): the
     * CGI still cannot read /home, /root, other vhosts' roots or /var outside
     * the unveiled logs/work, and cannot write anywhere but its granted
     * writable paths. Without execpromises (wrapped CGI) these are harmless
     * extra grants. Only added when the config actually execs a program. */
    if (sandbox_need_exec) {
        sandbox_add_path("/bin", "rx");
        sandbox_add_path("/sbin", "rx");
        sandbox_add_path("/usr", "rx");
    }
#endif

#ifdef __linux__
	if (sandbox_need_exec) {
		/* Broad read+exec on the system trees so any CGI interpreter (perl,
		 * python, php) finds its binary, shared libraries AND its data/module
		 * trees — Debian keeps interpreter code under /usr/lib, but /usr/share
		 * and /usr/local hold modules/data for many others. This mirrors the
		 * OpenBSD CGI-runtime grant for one uniform "broad system read" policy.
		 * Still far tighter than the pre-sandbox whole filesystem: /home, /root,
		 * /var (outside the unveiled logs/work) and other document roots stay
		 * hidden via Landlock, and nothing granted here is writable. */
		sandbox_add_path("/usr", "rx");
		sandbox_add_path("/bin", "rx");
		sandbox_add_path("/sbin", "rx");
		sandbox_add_path("/lib", "rx");
		sandbox_add_path("/lib64", "rx");
	} else {
		sandbox_add_path("/usr/lib", "r");
		sandbox_add_path("/lib", "r");
	}
	sandbox_add_path("/etc/ld.so.cache", "r");

#ifdef ENABLE_LOADCHECK
	/* The task_runner thread reads /proc/loadavg every second when MaxServerLoad
	 * is set (getloadavg / the HAVE_GETLOADAVG fallback both open it). Without this
	 * the read fails, the load stays pinned at 0 and the overload gate never trips. */
	if (config->max_server_load > 0) {
		sandbox_add_path("/proc/loadavg", "r");
	}
#endif
#endif

	return 0;
}

/* Phase 0 -- reject configurations the sandbox cannot honestly confine.
 * Returns true when the running config is compatible with the sandbox; on an
 * incompatible directive it prints which one (and how to resolve it) and returns
 * false. Deliberately conservative: only directives that DEMONSTRABLY break or
 * defeat confinement are rejected, so a working setup is never turned away. Both
 * problems are reported in one pass so the admin can resolve them together
 * instead of one restart at a time.
 *
 * Only checked on platforms whose sandbox_apply() actually enforces: on the
 * no-op fallback platform the sandbox does nothing, so no config can conflict
 * and rejecting one would be a pointless fatal.
 *
 * Deliberately NOT rejected here -- documented request-time gaps that only
 * *conditionally* break, so a hard reject would turn working setups away:
 *   - UseLocalConfig: a per-request .hiawatha may pull in out-of-tree paths,
 *     exec or writes the static collect never saw, but one that stays inside the
 *     document tree works fine under the sandbox.
 *   - X-Sendfile: a CGI-chosen response path with no config toggle at all; a
 *     target outside every granted path fails, one inside works -- undetectable
 *     from config. */
bool sandbox_check_config(t_config *config) {
	bool compatible = true;

#if defined(__OpenBSD__) || defined(__linux__) || defined(__APPLE__)
	t_host *host;

	/* UserWebsites (/~user/): the document root is resolved per request via
	 * getpwnam() and may be any user's home tree. Those paths are unknown when
	 * sandbox_collect_paths() runs, and the unveil/Landlock/Seatbelt ruleset is
	 * locked before the first request is served -- so it can never grant them and
	 * every /~user/ request would fail under the sandbox. Incompatible on all
	 * enforcing platforms until a design exists (getpw promise + per-home grant). */
	for (host = config->first_host; host != NULL; host = host->next) {
		if (host->user_websites) {
			fprintf(stderr, "Sandbox: EnableSandbox is incompatible with UserWebsites "
			        "(per-user document roots cannot be granted before privileges are "
			        "dropped). Disable UserWebsites or EnableSandbox.\n");
			compatible = false;
			break;
		}
	}
#else
	/* No-op sandbox platform: nothing is enforced, so nothing can conflict. */
	(void)config;
#endif

#ifdef __linux__
	/* WrapCGI on Linux: the sandbox must set PR_SET_NO_NEW_PRIVS (required for
	 * unprivileged seccomp and for Landlock). That flag makes the setuid
	 * cgi-wrapper's setuid() fail with EPERM, so a wrapped CGI can never start.
	 * OpenBSD instead skips execpromises for wrapped CGI (the wrapper's own chroot
	 * confines it); Linux has no equivalent carve-out yet. */
	if (sandbox_uses_wrap_cgi(config)) {
		fprintf(stderr, "Sandbox: EnableSandbox is incompatible with WrapCGI on Linux "
		        "(NO_NEW_PRIVS defeats the setuid cgi-wrapper). Disable WrapCGI or "
		        "EnableSandbox.\n");
		compatible = false;
	}
#endif

	return compatible;
}

#if defined(__OpenBSD__)
/* OpenBSD pledge promise string, extended from the running config: the base
 * promises plus "exec" (server execs a program) and/or "unix" (AF_UNIX backend
 * socket). Shared by sandbox_print_paths() and sandbox_apply() so the two can
 * never drift apart. */
static const char *sandbox_promises(void) {
	static char promises[128];

	strlcpy(promises, "stdio rpath wpath cpath fattr inet dns proc", sizeof(promises));
	if (sandbox_need_exec) {
		strlcat(promises, " exec", sizeof(promises));
	}
	if (sandbox_need_unix) {
		strlcat(promises, " unix", sizeof(promises));
	}

	return promises;
}

/* execpromises: the pledge applied to programs the server execs (CGI,
 * RunOnDownload/RunOnAlter). Passing a non-NULL execpromises is what keeps the
 * child pledged AND keeps the parent's unveil view in force across execve — so
 * a CGI is confined to the unveiled paths (its document root and the CGI
 * runtime), matching what Landlock/Seatbelt already do on Linux/macOS. Without
 * it (NULL) the child runs "without pledge active" and unveil is lifted, i.e.
 * the CGI can read and write anywhere its uid allows — the sandbox would not
 * cover the request/CGI path at all.
 *
 * The set is deliberately generous: the security win is the unveil filesystem
 * confinement, not tight syscall filtering, so ordinary CGIs keep working.
 * "tmppath" is intentionally omitted — it would grant /tmp access that bypasses
 * unveil. Returns NULL (no execpromises) when nothing is exec'd, or when a
 * setuid cgi-wrapper is in use (execpromises + setuid target => execve EACCES;
 * those setups are confined by the wrapper's chroot instead). */
static const char *sandbox_execpromises(void) {
	if ((sandbox_need_exec == false) || sandbox_need_wrap) {
		return NULL;
	}

	return "stdio rpath wpath cpath fattr flock chown getpw "
	       "inet dns unix sendfd recvfd tty proc exec prot_exec";
}
#endif

void sandbox_print_paths(void) {
#if defined(__OpenBSD__) || defined(__linux__) || defined(__APPLE__)
	int i;
#endif

	printf("sandbox:");
#if defined(__OpenBSD__)
	printf(" pledge/unveil\n");
	printf("  promises: %s\n", sandbox_promises());
	{
		const char *ep = sandbox_execpromises();
		printf("  execpromises: %s\n", (ep != NULL) ? ep : "(none — exec'd CGI not confined)");
	}
	for (i = 0; i < sandbox_path_count; i++) {
		printf("  unveil: %s (%s)\n", sandbox_paths[i].path, sandbox_paths[i].perms);
	}
#elif defined(__linux__)
	printf(" landlock/seccomp\n");
	for (i = 0; i < sandbox_path_count; i++) {
		printf("  path: %s (%s)\n", sandbox_paths[i].path, sandbox_paths[i].perms);
	}
#elif defined(__APPLE__)
	printf(" seatbelt\n");
	for (i = 0; i < sandbox_path_count; i++) {
		printf("  path: %s (%s)\n", sandbox_paths[i].path, sandbox_paths[i].perms);
	}
#else
	printf(" none\n");
#endif
}

#if !defined(__APPLE__)
/* Only macOS applies the sandbox by re-exec'ing under sandbox-exec; on every
 * other platform the sandbox is applied in-place by sandbox_apply(), so the
 * pre-bind re-exec hook is a no-op here. */
int sandbox_reexec(void) {
	return 0;
}
#endif

/* =========================================================================
 * OpenBSD: pledge(2) + unveil(2)
 * =========================================================================
 */
#if defined(__OpenBSD__)

#include <unistd.h>

int sandbox_apply(void) {
	int i;

	for (i = 0; i < sandbox_path_count; i++) {
		if (unveil(sandbox_paths[i].path, sandbox_paths[i].perms) == -1) {
			fprintf(stderr, "Sandbox: unveil(%s) failed, continuing.\n",
			        sandbox_paths[i].path);
		}
	}

	if (unveil(NULL, NULL) == -1) {
		fprintf(stderr, "Sandbox: unveil lock failed, continuing.\n");
	}

	if (pledge(sandbox_promises(), sandbox_execpromises()) == -1) {
		fprintf(stderr, "Sandbox: pledge failed, continuing.\n");
		return -1;
	}

	fprintf(stdout, "Sandbox: OpenBSD pledge/unveil applied.\n");
	return 0;
}

/* =========================================================================
 * Linux: Landlock + seccomp-bpf
 * =========================================================================
 */
#elif defined(__linux__)

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <linux/landlock.h>

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1 << 0)
#endif

/* For the seccomp(2) syscall with thread-sync (see apply_seccomp). Defined here
 * for kernels whose userspace headers predate them; the syscall is what matters. */
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC (1UL << 0)
#endif

static int landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
                                    size_t size, __u32 flags) {
	return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static int landlock_add_rule(int ruleset_fd,
                              enum landlock_rule_type rule_type,
                              const void *rule_attr, __u32 flags) {
	return (int)syscall(__NR_landlock_add_rule, ruleset_fd, rule_type,
	                    rule_attr, flags);
}

static int landlock_restrict_self(int ruleset_fd, __u32 flags) {
	return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

static __u64 perms_to_landlock_dir(const char *perms) {
	__u64 access = 0;

	if (perms == NULL) {
		return 0;
	}

	if (strchr(perms, 'r') != NULL) {
		access |= LANDLOCK_ACCESS_FS_READ_FILE |
		           LANDLOCK_ACCESS_FS_READ_DIR;
	}
	if (strchr(perms, 'w') != NULL) {
		access |= LANDLOCK_ACCESS_FS_WRITE_FILE |
		           LANDLOCK_ACCESS_FS_REMOVE_FILE |
		           LANDLOCK_ACCESS_FS_REMOVE_DIR;
	}
	if (strchr(perms, 'c') != NULL) {
		access |= LANDLOCK_ACCESS_FS_MAKE_CHAR |
		           LANDLOCK_ACCESS_FS_MAKE_DIR |
		           LANDLOCK_ACCESS_FS_MAKE_REG;
	}
	if (strchr(perms, 'x') != NULL) {
		access |= LANDLOCK_ACCESS_FS_EXECUTE;
	}

	return access;
}

/* Access mask for a rule attached to a single non-directory fd. Landlock
 * accepts file fds ("parent_fd ... or just a file"), but only with the
 * file-applicable rights; directory rights (READ_DIR, MAKE_*, REMOVE_*) on a
 * file fd give EINVAL. */
static __u64 perms_to_landlock_file(const char *perms) {
	__u64 access = 0;

	if (perms == NULL) {
		return 0;
	}

	if (strchr(perms, 'r') != NULL) {
		access |= LANDLOCK_ACCESS_FS_READ_FILE;
	}
	if (strchr(perms, 'w') != NULL) {
		access |= LANDLOCK_ACCESS_FS_WRITE_FILE;
	}
	if (strchr(perms, 'x') != NULL) {
		access |= LANDLOCK_ACCESS_FS_EXECUTE;
	}

	return access;
}

static int add_landlock_path(int ruleset_fd, const char *path, const char *perms) {
	struct stat st;
	int fd;
	__u64 access;
	struct landlock_path_beneath_attr path_beneath = {0};
	char parent[4096];
	const char *open_path;
	char *slash;

	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			open_path = path;
			access = perms_to_landlock_dir(perms);
		} else if (strchr(perms, 'c') == NULL) {
			/* Existing file or device without the create permission: attach the
			 * rule to the file itself, with the file-applicable access mask.
			 * Granting the parent directory instead (as before) silently widened
			 * e.g. "/etc/ld.so.cache (r)" to all of /etc — Linux must be as
			 * path-precise as unveil on OpenBSD. The rule binds to the inode,
			 * which is fine for these stable paths; anything (re)created at
			 * runtime goes through the create branch below. */
			open_path = path;
			access = perms_to_landlock_file(perms);
		} else {
			/* File that may be (re)created at runtime (logfiles: fopen "a"
			 * implies O_CREAT): creation needs MAKE_REG on the directory, so
			 * the rule must go on the parent — this widening is semantically
			 * required, and it keeps working across log rotation. */
			strlcpy(parent, path, sizeof(parent));
			slash = strrchr(parent, '/');
			if ((slash != NULL) && (slash != parent)) {
				*slash = '\0';
			} else if (slash == parent) {
				parent[1] = '\0';
			}
			open_path = parent;
			access = perms_to_landlock_dir(perms);
		}
	} else {
		// Path doesn't exist yet — open parent directory
		strlcpy(parent, path, sizeof(parent));
		slash = strrchr(parent, '/');
		if ((slash != NULL) && (slash != parent)) {
			*slash = '\0';
		} else if (slash == parent) {
			parent[1] = '\0';
		}
		open_path = parent;
		access = perms_to_landlock_dir(perms);
	}

	if (access == 0) {
		return 0;
	}

	fd = open(open_path, O_PATH | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}

	path_beneath.allowed_access = access;
	path_beneath.parent_fd = fd;

	if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
	                      &path_beneath, 0) != 0) {
		fprintf(stderr, "Sandbox: landlock_add_rule(%s) failed (errno=%d), continuing.\n",
		        path, errno);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static int apply_landlock(void) {
	int ruleset_fd, i, success_count, abi;
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs =
			LANDLOCK_ACCESS_FS_READ_FILE |
			LANDLOCK_ACCESS_FS_READ_DIR |
			LANDLOCK_ACCESS_FS_WRITE_FILE |
			LANDLOCK_ACCESS_FS_REMOVE_FILE |
			LANDLOCK_ACCESS_FS_REMOVE_DIR |
			LANDLOCK_ACCESS_FS_MAKE_CHAR |
			LANDLOCK_ACCESS_FS_MAKE_DIR |
			LANDLOCK_ACCESS_FS_MAKE_REG |
			LANDLOCK_ACCESS_FS_EXECUTE,
	};

	abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0) {
		fprintf(stderr, "Sandbox: Landlock not supported (kernel too old?), continuing.\n");
		return -1;
	}

	ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	if (ruleset_fd < 0) {
		fprintf(stderr, "Sandbox: landlock_create_ruleset failed, continuing.\n");
		return -1;
	}

	success_count = 0;
	for (i = 0; i < sandbox_path_count; i++) {
		if (add_landlock_path(ruleset_fd, sandbox_paths[i].path,
		                      sandbox_paths[i].perms) == 0) {
			success_count++;
		}
	}

	if (success_count == 0) {
		fprintf(stderr, "Sandbox: no Landlock rules applied, skipping enforcement.\n");
		close(ruleset_fd);
		return -1;
	}

	/* PR_SET_NO_NEW_PRIVS is set once, up front, in sandbox_apply(). */
	if (landlock_restrict_self(ruleset_fd, 0) != 0) {
		fprintf(stderr, "Sandbox: landlock_restrict_self failed, continuing.\n");
		close(ruleset_fd);
		return -1;
	}

	close(ruleset_fd);
	return 0;
}

static int apply_seccomp(void) {
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_readv, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_writev, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kexec_load, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

#ifdef __NR_kexec_file_load
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kexec_file_load, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
#endif

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_init_module, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_finit_module, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_delete_module, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mount, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_umount2, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pivot_root, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_reboot, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_swapon, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_swapoff, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sethostname, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setdomainname, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

		/* Allow everything else */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};

	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	/* Install via the seccomp(2) syscall with SECCOMP_FILTER_FLAG_TSYNC rather
	 * than prctl(PR_SET_SECCOMP): TSYNC applies the filter to EVERY thread in the
	 * process, not just the caller. This gives Linux the same process-wide reach
	 * that pledge has on OpenBSD, despite the different mechanism — the syscall
	 * filter then holds regardless of when a thread was created. (The primary
	 * guarantee is still ordering: sandbox_apply() runs before the worker pool is
	 * spawned; TSYNC is defense-in-depth so a stray earlier thread can't slip the
	 * syscall filter. Note it cannot do the same for Landlock — the filesystem
	 * side has no cross-thread call and truly depends on the spawn-order.)
	 * TSYNC returns 0 on success, or the TID of a thread that could not be synced;
	 * treat any non-zero the same as prctl's failure. Fall back to the prctl path
	 * on EINVAL/ENOSYS so an old kernel without the seccomp(2) syscall still gets
	 * the caller-thread filter. */
	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog) != 0) {
		if ((errno == ENOSYS) || (errno == EINVAL)) {
			if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
				fprintf(stderr, "Sandbox: seccomp filter failed, continuing.\n");
				return -1;
			}
		} else {
			fprintf(stderr, "Sandbox: seccomp filter failed, continuing.\n");
			return -1;
		}
	}

	return 0;
}

int sandbox_apply(void) {
	int result = 0;

	/* NO_NEW_PRIVS is required both for unprivileged seccomp (PR_SET_SECCOMP)
	 * and for Landlock (landlock_restrict_self). Set it once up front so that
	 * seccomp still applies even when Landlock is unsupported and bails out —
	 * previously it lived inside apply_landlock(), coupling seccomp enforcement
	 * to Landlock succeeding. */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		fprintf(stderr, "Sandbox: prctl(NO_NEW_PRIVS) failed, continuing.\n");
	}

	if (apply_landlock() == 0) {
		fprintf(stdout, "Sandbox: Linux Landlock applied.\n");
	} else {
		result = -1;
	}

	if (apply_seccomp() == 0) {
		fprintf(stdout, "Sandbox: Linux seccomp applied.\n");
	} else {
		result = -1;
	}

	return result;
}

/* =========================================================================
 * macOS: Seatbelt (sandbox-exec re-exec)
 * =========================================================================
 */
#elif defined(__APPLE__)

#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdint.h>
#include <errno.h>
#include <poll.h>
#include <mach-o/dyld.h>

/* Write an SBPL-safe string, escaping backslashes and double quotes */
static void sbpl_write_path(FILE *fp, const char *path) {
	const char *p;

	for (p = path; *p != '\0'; p++) {
		if ((*p == '"') || (*p == '\\')) {
			fputc('\\', fp);
		}
		fputc(*p, fp);
	}
}

static int generate_seatbelt_profile(int profile_fd) {
	FILE *fp;
	int i;
	const char *path;
	const char *perms;

	fp = fdopen(profile_fd, "w");
	if (fp == NULL) {
		fprintf(stderr, "Sandbox: cannot open seatbelt profile fd, continuing.\n");
		close(profile_fd);
		return -1;
	}

	fprintf(fp, "(version 1)\n");
	fprintf(fp, "(deny default)\n");
	/* Import the OS baseline profile (dyld shared cache, sysctl, mach bootstrap,
	 * standard system libraries). A from-scratch deny-default profile cannot
	 * enumerate everything a process needs just to start under Seatbelt.
	 * deny-default stays in effect, so only this baseline plus the explicit
	 * allows below are permitted; arbitrary file access remains denied. */
	fprintf(fp, "(import \"system.sb\")\n\n");

	fprintf(fp, "(allow process-fork)\n");
	fprintf(fp, "(allow sysctl-read)\n");
	fprintf(fp, "(allow mach-lookup)\n");
	fprintf(fp, "(allow signal)\n\n");

	fprintf(fp, "(allow network*)\n\n");

	fprintf(fp, "(allow file-read-data file-write-data\n");
	fprintf(fp, "  (literal \"/dev/null\")\n");
	fprintf(fp, "  (literal \"/dev/urandom\")\n");
	fprintf(fp, "  (literal \"/dev/random\")\n");
	fprintf(fp, "  (subpath \"/dev/fd\"))\n\n");

	for (i = 0; i < sandbox_path_count; i++) {
		path = sandbox_paths[i].path;
		perms = sandbox_paths[i].perms;

		if ((strchr(perms, 'w') != NULL) || (strchr(perms, 'c') != NULL)) {
			fprintf(fp, "(allow file-read* file-write*\n");
			fprintf(fp, "  (subpath \"");
			sbpl_write_path(fp, path);
			fprintf(fp, "\"))\n");
		} else {
			fprintf(fp, "(allow file-read*\n");
			fprintf(fp, "  (subpath \"");
			sbpl_write_path(fp, path);
			fprintf(fp, "\"))\n");
		}

		if (strchr(perms, 'x') != NULL) {
			fprintf(fp, "(allow process-exec*\n");
			fprintf(fp, "  (subpath \"");
			sbpl_write_path(fp, path);
			fprintf(fp, "\"))\n");
		}
	}

	fprintf(fp, "\n(allow file-read*\n");
	fprintf(fp, "  (subpath \"/usr/lib\")\n");
	fprintf(fp, "  (subpath \"/usr/local/lib\")\n");
	fprintf(fp, "  (subpath \"/usr/local/opt\")\n");
	fprintf(fp, "  (subpath \"/usr/local/Cellar\")\n");
	fprintf(fp, "  (subpath \"/System/Library\"))\n");

	/* The re-exec'd process re-runs the whole startup under this profile, so it
	 * must read its own executable + bundled dylibs (for a user-run build these
	 * live next to the binary, not in /usr/local/lib) and re-read its config
	 * (hiawatha has already chdir'd into the config directory). Grant read on
	 * the executable's directory and the current working directory. */
	{
		char buf[PATH_MAX];
		uint32_t exelen = sizeof(buf);
		char *slash;

		if (_NSGetExecutablePath(buf, &exelen) == 0) {
			slash = strrchr(buf, '/');
			if ((slash != NULL) && (slash != buf)) {
				*slash = '\0';
				fprintf(fp, "\n(allow file-read*\n  (subpath \"");
				sbpl_write_path(fp, buf);
				fprintf(fp, "\"))\n");
				/* The re-exec runs hiawatha (and, for a user-run build, its
				 * bundled helpers) from this directory under the profile, so it
				 * needs process-exec here. Broad exec is NOT granted: CGI
				 * interpreters get process-exec per-path above, and only when a
				 * config actually execs a program. */
				fprintf(fp, "(allow process-exec*\n  (subpath \"");
				sbpl_write_path(fp, buf);
				fprintf(fp, "\"))\n");
			}
		}
		if (getcwd(buf, sizeof(buf)) != NULL) {
			fprintf(fp, "(allow file-read*\n  (subpath \"");
			sbpl_write_path(fp, buf);
			fprintf(fp, "\"))\n");
		}
	}

	fclose(fp);
	return 0;
}

/* Re-exec handshake, without any environment variable.
 *
 * The ONLY user-facing switch for the sandbox is EnableSandbox in the
 * configuration. Internally the parent must tell its sandbox-exec'd child
 * "you are the re-exec, do not re-exec again" — and an environment variable
 * is the wrong vehicle for that: a stale or inherited value (old shell
 * session, launchd environment, previous test run) once made the server skip
 * the re-exec silently and run WITHOUT Seatbelt while reporting it active.
 *
 * Instead the parent dup2()s the read end of a pipe, filled with
 * SANDBOX_REEXEC_MAGIC, onto the fixed descriptor SANDBOX_REEXEC_FD right
 * before exec'ing sandbox-exec. The child proves it is the re-exec by reading
 * the magic back from that descriptor. File descriptors are not inherited
 * from unrelated shell sessions, cannot linger in launchd, and are invisible
 * to CGI programs (the verified child closes the descriptor immediately), so
 * the whole stale-environment failure class is gone by construction. This is
 * not a defense against a hostile same-uid launcher — such a launcher could
 * start hiawatha without the sandbox in the first place.
 *
 * If the descriptor is absent, not a pipe, or holds anything but the magic,
 * the process simply is not the re-exec child and re-execs; that always
 * converges, because the child it creates does get the magic pipe. */
#define SANDBOX_REEXEC_FD 197
#define SANDBOX_REEXEC_MAGIC "HiaWaSbx"
#define SANDBOX_REEXEC_MAGIC_LEN (sizeof(SANDBOX_REEXEC_MAGIC) - 1)

/* Returns true if this process is the verified re-exec'd child. Only a pipe
 * with data already waiting is ever read (the parent buffers the magic before
 * exec), and only a verified descriptor is closed — anything else at that fd
 * number is left untouched and can never block. */
static bool is_reexec_child(void) {
	char buf[SANDBOX_REEXEC_MAGIC_LEN];
	struct stat sb;
	struct pollfd pfd;
	int ready;
	ssize_t n;

	if ((fstat(SANDBOX_REEXEC_FD, &sb) == -1) || (S_ISFIFO(sb.st_mode) == 0)) {
		return false;
	}
	pfd.fd = SANDBOX_REEXEC_FD;
	pfd.events = POLLIN;
	pfd.revents = 0;
	do {
		ready = poll(&pfd, 1, 0);
	} while ((ready == -1) && (errno == EINTR));
	if ((ready != 1) || ((pfd.revents & POLLIN) == 0)) {
		return false;
	}
	do {
		n = read(SANDBOX_REEXEC_FD, buf, sizeof(buf));
	} while ((n == -1) && (errno == EINTR));
	if ((n != (ssize_t)SANDBOX_REEXEC_MAGIC_LEN) || (memcmp(buf, SANDBOX_REEXEC_MAGIC, SANDBOX_REEXEC_MAGIC_LEN) != 0)) {
		return false;
	}
	close(SANDBOX_REEXEC_FD);

	return true;
}

int sandbox_reexec(void) {
	char profile_path[256];
	int handshake_pipe[2];
	pid_t pid;
	int status, profile_fd;
	extern char ***_NSGetArgv(void);
	extern int *_NSGetArgc(void);
	char **argv;
	int argc, j;
	char **new_argv;
	char exe_path[PATH_MAX];
	uint32_t exe_size;

	if (is_reexec_child()) {
		fprintf(stdout, "Sandbox: macOS Seatbelt active (re-exec verified).\n");
		return 0;
	}

	/* Create temp file with unpredictable name to prevent symlink attacks */
	strlcpy(profile_path, "/tmp/hiawatha-sandbox-XXXXXX", sizeof(profile_path));
	profile_fd = mkstemp(profile_path);
	if (profile_fd == -1) {
		fprintf(stderr, "Sandbox: mkstemp failed, continuing without sandbox.\n");
		return -1;
	}

	if (generate_seatbelt_profile(profile_fd) != 0) {
		unlink(profile_path);
		return -1;
	}

	if (pipe(handshake_pipe) == -1) {
		fprintf(stderr, "Sandbox: pipe failed, continuing without sandbox.\n");
		unlink(profile_path);
		return -1;
	}
	if (write(handshake_pipe[1], SANDBOX_REEXEC_MAGIC, SANDBOX_REEXEC_MAGIC_LEN) != SANDBOX_REEXEC_MAGIC_LEN) {
		fprintf(stderr, "Sandbox: writing re-exec handshake failed, continuing without sandbox.\n");
		close(handshake_pipe[0]);
		close(handshake_pipe[1]);
		unlink(profile_path);
		return -1;
	}
	/* Close the write end now: the magic stays buffered in the pipe and the
	 * child's read hits EOF right after it. */
	close(handshake_pipe[1]);

	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Sandbox: fork failed, continuing without sandbox.\n");
		close(handshake_pipe[0]);
		unlink(profile_path);
		return -1;
	}

	if (pid == 0) {
		/* Child: park the magic pipe on the fixed descriptor, then re-exec
		 * under sandbox-exec. dup2 clears any close-on-exec flag. */
		if (handshake_pipe[0] != SANDBOX_REEXEC_FD) {
			if (dup2(handshake_pipe[0], SANDBOX_REEXEC_FD) == -1) {
				fprintf(stderr, "Sandbox: dup2 failed.\n");
				_exit(1);
			}
			close(handshake_pipe[0]);
		}

		// Get original argv — on macOS we use _NSGetArgv
		argv = *_NSGetArgv();
		argc = *_NSGetArgc();

		/* Re-exec the server by its ABSOLUTE path, not argv[0]: when hiawatha is
		 * started with a relative argv[0] (e.g. ./hiawatha), execvp() of that path
		 * under sandbox-exec fails. _NSGetExecutablePath() returns the absolute
		 * path, which also matches the process-exec subpath granted in the profile. */
		exe_size = sizeof(exe_path);
		if (_NSGetExecutablePath(exe_path, &exe_size) != 0) {
			fprintf(stderr, "Sandbox: cannot resolve executable path, continuing.\n");
			_exit(1);
		}

		// Build sandbox-exec command
		new_argv = malloc((argc + 4) * sizeof(char *));
		if (new_argv == NULL) {
			_exit(1);
		}
		new_argv[0] = "sandbox-exec";
		new_argv[1] = "-f";
		new_argv[2] = profile_path;
		new_argv[3] = exe_path;
		for (j = 1; j < argc; j++) {
			new_argv[j + 3] = argv[j];
		}
		new_argv[argc + 3] = NULL;

		/* Absolute path, no PATH lookup: the "Seatbelt active" report is only
		 * as trustworthy as the wrapper that was exec'd. */
		execv("/usr/bin/sandbox-exec", new_argv);
		fprintf(stderr, "Sandbox: sandbox-exec failed, continuing.\n");
		_exit(1);
	}

	// Parent: wait for sandboxed child
	close(handshake_pipe[0]);
	waitpid(pid, &status, 0);
	unlink(profile_path);

	if (WIFEXITED(status)) {
		exit(WEXITSTATUS(status));
	}
	exit(1);
}

/* The sandbox is already applied (by the earlier sandbox_reexec() re-exec);
 * nothing left to do at the normal apply point on macOS. */
int sandbox_apply(void) {
	return 0;
}

/* =========================================================================
 * Other platforms: No-op
 * =========================================================================
 */
#else

int sandbox_apply(void) {
	fprintf(stderr, "Sandbox: no sandbox support on this platform.\n");
	return -1;
}

#endif

#endif
