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

#ifndef _TLS_H
#define _TLS_H

#include "config.h"

#ifdef ENABLE_TLS

#define TLS_context mbedtls_ssl_context
#define TLS_config  mbedtls_ssl_config
#define TLS_key     mbedtls_pk_context
#define TLS_cert    mbedtls_x509_crt
#define TLS_crl     mbedtls_x509_crl

#include <stdbool.h>
#include "liblist.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/version.h"

#define TLS_HANDSHAKE_OKE       0
#define TLS_HANDSHAKE_ERROR    -1
#define TLS_HANDSHAKE_TIMEOUT  -2
#define TLS_HANDSHAKE_NO_MATCH -3

#ifdef ENABLE_DEBUG
#define TLS_ERROR_LOGFILE LOG_DIR"/tls_debug.log"
#endif

typedef struct {
	TLS_key  *private_key;
	TLS_cert *certificate;
	TLS_cert *ca_certificate;
	TLS_crl  *ca_crl;
} t_tls_setup;

typedef struct type_hpkp_data {
	char             *cert_file;
	int              max_age;
	char             *http_header;
	size_t           header_size;

	struct type_hpkp_data *next;
} t_hpkp_data;

int  init_tls_module();
int  init_ca_certificats(char *ca_cert_files, mbedtls_x509_crt **ca_certificates);
int  tls_set_config(TLS_config **tls_config, t_tls_setup *tls_setup);
#ifdef ENABLE_HTTP2
int  tls_enable_alpn(mbedtls_ssl_config **tls_config);
#endif
int  tls_register_sni(t_charlist *hostname, t_tls_setup *tls_setup);
int  tls_load_key_cert(char *file, TLS_key **private_key, TLS_cert **certificate);
int  tls_load_ca_cert(char *file, TLS_cert **ca_certificate);
int  tls_load_ca_crl(char *file, TLS_crl **ca_crl);
int  tls_accept(int *sock, TLS_context *context, TLS_config *config, int timeout);
int  tls_pending(TLS_context *context);
int  tls_receive(TLS_context *context, char *buffer, unsigned int maxlength);
int  tls_send(TLS_context *context, const char *buffer, unsigned int length);
bool tls_has_peer_cert(TLS_context *context);
int  tls_get_peer_cert_info(TLS_context *context, char *subject_dn, char *issuer_dn, char *serial_nr, int length);
char *tls_version_string(TLS_context *context);
char *tls_cipher_string(TLS_context *context);
void tls_close(TLS_context *context);
#ifdef ENABLE_HTTP2
const char *tls_get_alpn_protocol(TLS_context *context);
#endif
int  tls_connect(TLS_context *context, int *sock, char *hostname);
int  tls_send_buffer(TLS_context *context, const char *buffer, int size);
int  create_hpkp_header(t_hpkp_data *hpkp_data);
#endif

#endif
