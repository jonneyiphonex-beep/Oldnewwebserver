/* sandbox.h -- OS-level sandboxing for Hiawatha
 *
 * Supports: OpenBSD (pledge/unveil), Linux (landlock/seccomp),
 *           macOS (Seatbelt), others (no-op with warning).
 *
 * Defense-in-depth: sandbox errors are never fatal.
 */

#ifndef _SANDBOX_H
#define _SANDBOX_H

#ifdef ENABLE_SANDBOX

#include "serverconfig.h"

/* Phase 0: Reject configurations the sandbox cannot honestly confine.
 * Some directives need request-time filesystem access that the static path
 * collection cannot express (dynamic per-user roots) or that fights the sandbox
 * mechanism itself (setuid under NO_NEW_PRIVS). Call after check_configuration(),
 * only when EnableSandbox is set. Returns true if the config is compatible; on an
 * incompatible directive it prints which one and how to resolve it, then returns
 * false. The caller decides what false means (see hiawatha.c).
 */
bool sandbox_check_config(t_config *config);

/* Phase 1: Collect filesystem paths from parsed config.
 * Call after read_main_configfile(), before privilege drop.
 * Returns 0 on success, -1 on error (logged, non-fatal).
 */
int sandbox_collect_paths(t_config *config);

/* Phase 2: Apply OS sandbox restrictions.
 * Call after change_uid_gid() / privilege drop.
 * Returns 0 on success, -1 on error (logged, non-fatal).
 */
int sandbox_apply(void);

/* macOS only: apply the sandbox by re-exec'ing the process under sandbox-exec.
 * Must be called before binding listening sockets (the re-exec restarts main(),
 * so binding first would double-bind -> EADDRINUSE). No-op on other platforms.
 * Returns 0 on success, -1 on error (logged, non-fatal).
 */
int sandbox_reexec(void);

/* Print collected sandbox paths (for -V output).
*/
void sandbox_print_paths(void);

#endif

#endif
