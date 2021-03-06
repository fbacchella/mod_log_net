#include <string.h>

#include <apr_hash.h>
#include "ap_config.h"
#include "ap_provider.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "mod_ssl.h" /* ssl_var_lookup */

#include "apr_strings.h"
#include "util_time.h"
#include "apr_lib.h"

#include <errno.h>

#include <iconv.h>

#include <msgpack.h>

module AP_MODULE_DECLARE_DATA log_net_module;

static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *ssl_var_lookup = NULL;

typedef struct log_entry_info_t {
    void (*pack_entry)(msgpack_object *mp_obj, request_rec *, struct log_entry_info_t *);
    const char *param;
    apr_table_t  *options;
    int final;
} log_entry_info_t;

typedef struct {
    const char   *host;
    apr_port_t    port;
    const char   *encoding;
    apr_table_t  *entries;
} log_net_config_t;

static log_net_config_t config;
static apr_socket_t    *udp_socket;
static apr_sockaddr_t  *server_addr;

/*
 * log_request_state holds request specific log data that is not
 * part of the request_rec.
 */
typedef struct {
    apr_time_t request_end_time;
} log_request_state;

/*********
 * Helpers
 */

static void msgpack_pack_ascii_string(msgpack_object *mp_obj, request_rec *r, const char* buffer)
{
    if (buffer == NULL || strlen(buffer) == 0) {
        return;
    }
    mp_obj->type = MSGPACK_OBJECT_STR;
    mp_obj->via.str.size = strlen(buffer);
    mp_obj->via.str.ptr = apr_pstrndup(r->pool, buffer, MAX_STRING_LEN);
}

static void msgpack_pack_encoded_string(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info, const char* buffer)
{
    if (buffer == NULL || strlen(buffer) == 0) {
        return;
    }
    char converted[MAX_STRING_LEN];
    char formatted[MAX_STRING_LEN];
    const char *send_buffer = buffer;
    const char *dst_encoding = NULL;
    if (info != NULL) {
        dst_encoding = apr_table_get(info->options, "encoding");
    }
    if (dst_encoding == NULL) {
        dst_encoding = "UTF-8";
    }
    // Don't convert if encoding are equals or converting from "real" ASCII (7 bits) to UTF-8
    if (strcmp(config.encoding, dst_encoding) != 0 &&
        !( strcmp(config.encoding, "ASCII") == 0 && strcmp(config.encoding, "UTF-8") == 0 )) {
        iconv_t converter = iconv_open(config.encoding, dst_encoding);
        if (converter == (iconv_t) -1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
                          "iconv: invalid conversion from %s to %s", config.encoding, dst_encoding);
            return;
        }
        size_t inbytesleft = strlen(buffer);
        char *incursor = (char *) buffer;
        size_t outbytesleft = MAX_STRING_LEN - 1;
        char *outcursor = converted;
        size_t done_converted = 0;
        do {
            done_converted = iconv(converter,
                                   &incursor, &inbytesleft,
                                   &outcursor, &outbytesleft);
            
            if (done_converted == -1 && (errno == EILSEQ || errno == EINVAL)) {
                incursor++;
                inbytesleft--;
                *outcursor++ = '?';
                outbytesleft--;
            }
        } while (done_converted != -1 && outbytesleft > 0 && inbytesleft > 0);
        *outcursor = '\0';
        iconv_close(converter);
        
        if (done_converted == -1) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, errno, r,
                          "iconv: unfinished conversion from %s to %s", config.encoding, dst_encoding);
            return;
        }
        send_buffer = converted;
    }
    const char *format;
    if (info != NULL && (format = apr_table_get(info->options, "format"))) {
        snprintf(formatted, MAX_STRING_LEN, format, buffer);
        send_buffer = formatted;
    }

    mp_obj->type = MSGPACK_OBJECT_STR;
    mp_obj->via.str.size = strlen(send_buffer);
    mp_obj->via.str.ptr = apr_pstrdup(r->pool, send_buffer);
}

static void find_multiple_headers(msgpack_object *mp_obj,
                                  request_rec *r,
                                  apr_table_t *table,
                                  const char *key)
{
    const apr_table_entry_t *t_end;
    struct sle {
        struct sle *next;
        const char *value;
        apr_size_t len;
    } *result_list, *rp;

    const apr_array_header_t *elts = apr_table_elts(table);

    if (elts->nelts == 0) {
        return;
    }

    const apr_table_entry_t *t_elt = (const apr_table_entry_t *)elts->elts;
    t_end = t_elt + elts->nelts;
    uint32_t count = 0;
    result_list = rp = NULL;

    do {
        if (strcasecmp(t_elt->key, key) == 0) {
            if (!result_list) {
                result_list = rp = apr_palloc(r->pool, sizeof(*rp));
            }
            else {
                rp = rp->next = apr_palloc(r->pool, sizeof(*rp));
            }

            rp->next = NULL;
            rp->value = t_elt->val;
            rp->len = strlen(rp->value);

            count++;
        }
        ++t_elt;
    } while (t_elt < t_end);

    if (result_list) {
        mp_obj->type= MSGPACK_OBJECT_ARRAY;
        mp_obj->via.array.size = 0;
        mp_obj->via.array.ptr = apr_palloc(r->pool, sizeof(msgpack_object) * count);
        rp = result_list;
        while (rp != NULL) {
            msgpack_pack_ascii_string(&mp_obj->via.array.ptr[mp_obj->via.array.size++], r, rp->value);
            rp = rp->next;
        }
    }
    return;
}

/*********
 * Resolve the values
 */

//%...B:  bytes sent, excluding HTTP headers.
static void log_bytes_sent(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    if (r->sent_bodyct) {
        mp_obj->type = MSGPACK_OBJECT_POSITIVE_INTEGER;
        mp_obj->via.u64 = r->bytes_sent;
    }
}

//%...{FOOBAR}C:  The contents of the HTTP cookie FOOBAR
static void log_cookie(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    const char *a = info->param;

    if (a == NULL) {
        return;
    }

    const char *cookies_entry;

    /*
     * This supports Netscape version 0 cookies while being tolerant to
     * some properties of RFC2109/2965 version 1 cookies:
     * - case-insensitive match of cookie names
     * - white space between the tokens
     * It does not support the following version 1 features:
     * - quoted strings as cookie values
     * - commas to separate cookies
     */

    if ((cookies_entry = apr_table_get(r->headers_in, "Cookie"))) {
        char *cookie, *last1, *last2;
        char *cookies = apr_pstrdup(r->pool, cookies_entry);
        
        while ((cookie = apr_strtok(cookies, ";", &last1))) {
            char *name = apr_strtok(cookie, "=", &last2);
            /* last2 points to the next char following an '=' delim,
               or the trailing NUL char of the string */
            char *value = last2;
            if (name && *name &&  value && *value) {
                char *last = value - 2;
                /* Move past leading WS */
                name += strspn(name, " \t");
                while (last >= name && apr_isspace(*last)) {
                    *last = '\0';
                    --last;
                }

                if (!strcasecmp(name, a)) {
                    /* last1 points to the next char following the ';' delim,
                     or the trailing NUL char of the string */
                    last = last1 - (*last1 ? 2 : 1);
                    /* Move past leading WS */
                    value += strspn(value, " \t");
                    while (last >= value && apr_isspace(*last)) {
                        *last = '\0';
                        --last;
                    }
                    msgpack_pack_encoded_string(mp_obj, r, info, value);
                    break;
                }
            }
            /* Iterate the remaining tokens using apr_strtok(NULL, ...) */
            cookies = NULL;
        }
    }
}

//%...{FOOBAR}e:  The contents of the environment variable FOOBAR
static void log_env_var(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    const char *a = info->param;

    if (a != NULL) {
        const char *value = apr_table_get(r->subprocess_env, a);
        msgpack_pack_encoded_string(mp_obj, r, info, value);
    }
}

//%...f:  filename
static void log_request_file(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    msgpack_pack_encoded_string(mp_obj, r, info, r->filename);
}

//%...h:  remote host
static void log_remote_host(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    const char *remote_host;
#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    const char *a = info->param;
    if (a != NULL && strcmp(a, "real") == 0) {
        remote_host = ap_get_remote_host(r->connection, r->per_dir_config,
                                         REMOTE_NAME, NULL);
    }
    else {
#if AP_MODULE_MAGIC_AT_LEAST(20120211,56)
        remote_host = ap_get_useragent_host(r, REMOTE_NAME, NULL);
#else
        remote_host = ap_get_remote_host(r->connection, r->per_dir_config,
                                         REMOTE_NAME, NULL);
#endif
    }
#else
    remote_host = ap_get_remote_host(r->connection,
                                     r->per_dir_config,
                                     REMOTE_NAME, NULL);
#endif
    msgpack_pack_encoded_string(mp_obj, r, info, remote_host);
}

//%...a:  remote IP-address
static void log_remote_address(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    const char *remote_addr;
#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    const char *a = info->param;
    if (a != NULL && strcmp(a, "real") == 0) {
        remote_addr = r->connection->client_ip;
    } else {
        remote_addr = r->useragent_ip;
    }
#else
    remote_addr = r->connection->remote_ip;
#endif
    msgpack_pack_ascii_string(mp_obj, r, remote_addr);
}

//%...A:  local IP-address
static void log_local_address(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    msgpack_pack_ascii_string(mp_obj, r, r->connection->local_ip);
}

//%...{Foobar}i:  The contents of Foobar: header line(s) in the request sent to the client.
static void log_header_in(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    const char *a = info->param;

    if (a != NULL) {
        const char *header = apr_table_get(r->headers_in, a);
        msgpack_pack_encoded_string(mp_obj, r, info, header);
    }
}

//%...k:  number of keepalive requests served over this connection
static void log_requests_on_connection(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    mp_obj->type = MSGPACK_OBJECT_POSITIVE_INTEGER;
    mp_obj->via.u64 = r->connection->keepalives ? r->connection->keepalives - 1 : 0;
}

//%...l:  remote logname (from identd, if supplied)
static void log_remote_logname(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    msgpack_pack_encoded_string(mp_obj, r, info, ap_get_remote_logname(r));
}

//%...{Foobar}n:  The contents of note "Foobar" from another module.
static void log_note(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    const char *a = info->param;

    if (a != NULL) {
        msgpack_pack_encoded_string(mp_obj, r, info, apr_table_get(r->notes, a));
    }
}

//%...{Foobar}o:  The contents of Foobar: header line(s) in the reply.
static void log_header_out(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    const char *a = info->param;

    if (a == NULL) {
        return;
    }

    if (!strcasecmp(a, "Content-type") && r->content_type) {
        const char *cp = ap_field_noparam(r->pool, r->content_type);
        msgpack_pack_encoded_string(mp_obj, r, info, cp);
    }
    else if (!strcasecmp(a, "Set-Cookie")) {
        find_multiple_headers(mp_obj, r, r->headers_out, a);
    }
    else {
        const char *cp = apr_table_get(r->headers_out, a);
        msgpack_pack_encoded_string(mp_obj, r, info, cp);
    }
}

//%...p:  the canonical port for the server
//%...{format}p: the canonical port for the server, or the actual local or remote port
// This match canonical or local format, default to canonical
static void log_server_port(msgpack_object *mp_obj, request_rec *r, log_entry_info_t* info)
{
    const char *a = info->param;

    apr_port_t port = -1;
    
    if (a == NULL || *a == '\0' || strcasecmp(a, "canonical") == 0) {
        port = r->server->port ? r->server->port : ap_default_port(r);
    }
    else if (strcasecmp(a, "local") == 0) {
        port = r->connection->local_addr->port;
    }
    mp_obj->type = MSGPACK_OBJECT_POSITIVE_INTEGER;
    mp_obj->via.u64 = port;
}

//%...p:  the canonical port for the server
//%...{format}p: the canonical port for the server, or the actual local or remote port
static void log_remote_port(msgpack_object *mp_obj, request_rec *r, log_entry_info_t* info)
{

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    apr_port_t port = r->useragent_addr->port;
#else
    apr_port_t port = r->connection->remote_addr->port;
#endif
    mp_obj->type = MSGPACK_OBJECT_POSITIVE_INTEGER;
    mp_obj->via.u64 = port;
}

//%...P:  the process ID of the child that serviced the request.
//%...{format}P: the process ID or thread ID of the child/thread that serviced the request
static void log_pid_tid(msgpack_object *mp_obj, request_rec *r, log_entry_info_t* info)
{
    const char *a = info->param;

    const char * pid_tid = NULL;
    if (a == NULL || *a == '\0' || strcasecmp(a, "pid") == 0) {
        pid_tid = ap_append_pid(r->pool, "", "");
    }
    else if (strcasecmp(a, "tid") == 0 || strcasecmp(a, "hextid") == 0) {
#if APR_HAS_THREADS
        apr_os_thread_t tid = apr_os_thread_current();
#else
        int tid = 0; /* APR will format "0" anyway but an arg is needed */
#endif
        pid_tid =  apr_psprintf(r->pool,
#if APR_MAJOR_VERSION > 1 || (APR_MAJOR_VERSION == 1 && APR_MINOR_VERSION >= 2)
                                /* APR can format a thread id in hex */
                                *a == 'h' ? "%pt" : "%pT",
#else
                                /* APR is missing the feature, so always use decimal */
                                "%pT",
#endif
                                &tid);
    }
    if (pid_tid != NULL) {
        msgpack_pack_ascii_string(mp_obj, r, pid_tid);
    }
}

//%...s:  status.  For requests that got internally redirected, this is status of the *original* request --- %...>s for the last.
static void log_status(msgpack_object *mp_obj, request_rec *r, log_entry_info_t* info)
{
    mp_obj->type = MSGPACK_OBJECT_POSITIVE_INTEGER;
    mp_obj->via.u64 = r->status;
}

//%...R:  The handler generating the response (if any).
static void log_handler(msgpack_object *mp_obj, request_rec *r, log_entry_info_t* info)
{
    msgpack_pack_ascii_string(mp_obj, r, r->handler);
}

/*********************************************
 * Helpers function for request time logging *
 *********************************************/

static apr_time_t get_request_end_time(request_rec *r)
{
    log_request_state *state = (log_request_state *)ap_get_module_config(r->request_config,
                                                                         &log_net_module);
    if (state == NULL) {
        state = apr_pcalloc(r->pool, sizeof(log_request_state));
        ap_set_module_config(r->request_config, &log_net_module, state);
    }
    if (state->request_end_time == 0) {
        state->request_end_time = apr_time_now();
    }
    return state->request_end_time;
}

static void store32(void *to, uint32_t num) {
    uint32_t val = htobe32(num);
    memcpy(to, &val, 4);
}

static void store64(void *to, uint64_t num) {
    uint64_t val = htobe64(num);
    memcpy(to, &val, 8);
}

static void log_msgpack_pack_timestamp(msgpack_object *mp_obj, request_rec *r, apr_time_t request_time) {
    apr_int64_t sec = apr_time_sec(request_time);
    apr_int64_t nsec = apr_time_usec(request_time) * 1000;
    uint32_t buf_len;
    char *buf;

    if ((sec >> 34) == 0) {
        uint64_t data64 = (nsec << 34) | sec;
        if ((data64 & 0xffffffff00000000L) == 0) {
            // timestamp 32
            buf_len = 4;
            buf = apr_pcalloc(r->pool, buf_len);
            store32(buf, data64);
        } else {
            // timestamp 64
            buf_len = 8;
            buf = apr_pcalloc(r->pool, buf_len);
            store64(buf, data64);
        }
     } else {
        // timestamp 96
        buf_len = 12;
         buf = apr_pcalloc(r->pool, buf_len);
        store32(&buf[0], nsec);
        store64(&buf[4], sec);
    }
    mp_obj->type = MSGPACK_OBJECT_EXT;
    mp_obj->via.ext.type = -1;
    mp_obj->via.ext.size = buf_len;
    mp_obj->via.ext.ptr = buf;
}

static void log_request_time_custom(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info,
                                    const char *a, apr_time_exp_t *xt)
{
    apr_size_t retcode;
    char tstr[MAX_STRING_LEN];
    apr_strftime(tstr, &retcode, sizeof(tstr), a, xt);
    msgpack_pack_encoded_string(mp_obj, r, info, tstr);
}

#define DEFAULT_REQUEST_TIME_SIZE 32

enum TIME_FMT
{
    CUSTOM, ISO8601, MSGPACK, ABS_SEC, ABS_MSEC, ABS_USEC, ABS_MSEC_FRAC, ABS_USEC_FRAC
};

//%...t:  time, in common log format time format
//%...{format}t:  The time, in the form given by format, which should be in strftime(3) format.
static void log_request_time(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    apr_time_t request_time;
    // Check info value, always called for @timestamp, but with NULL info
    const char *a = info != NULL ? info->param : NULL;
    if (a != NULL && strcmp(a, "end") == 0) {
        request_time = get_request_end_time(r);
    } else if (a == NULL || strcmp(a, "begin") == 0){
        request_time = r->request_time;
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "Invalid time selection: %s", a);
        return;
    }

    const char *format = NULL;
    if (info != NULL) {
        format = apr_table_get(info->options, "format");
    }
    enum TIME_FMT fmt_type;
    if (format == NULL) {
        fmt_type = MSGPACK;
    } else if (strcmp(format, "sec") == 0) {
        fmt_type = ABS_SEC;
    } else if (strcmp(format, "msec") == 0) {
        fmt_type = ABS_MSEC;
    } else if (strcmp(format, "usec") == 0) {
        fmt_type = ABS_USEC;
    } else if (strcmp(format, "msec_frac") == 0) {
        fmt_type = ABS_MSEC_FRAC;
    } else if (strcmp(format, "usec_frac") == 0) {
        fmt_type = ABS_USEC_FRAC;
    } else if (strcmp(format, "iso8601") == 0) {
        fmt_type = ISO8601;
    } else {
        fmt_type = CUSTOM;
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "request timestamp: %ld, format: %d", request_time, fmt_type);

    switch (fmt_type) {
        case CUSTOM: {  /* Custom format */
            /* The custom time formatting uses a very large temp buffer
             * on the stack.  To avoid using so much stack space in the
             * common case where we're not using a custom format, the code
             * for the custom format in a separate function.  (That's why
             * log_request_time_custom is not inlined right here.)
             */
            apr_time_exp_t xt;
            ap_explode_recent_localtime(&xt, request_time);
            log_request_time_custom(mp_obj, r, info, format, &xt);
            break;
        }
        case MSGPACK:  /* Msgpack timestamp extension */
            log_msgpack_pack_timestamp(mp_obj, r, request_time);
            break;
        case ISO8601:  /* ISO 8601 format */ {
            char timestr[DEFAULT_REQUEST_TIME_SIZE];
            char sign;
            int timz;
            apr_time_exp_t xt;

            ap_explode_recent_localtime(&xt, request_time);
            timz = xt.tm_gmtoff;
            if (timz < 0) {
                timz = -timz;
                sign = '-';
            }
            else {
                sign = '+';
            }

            apr_snprintf(timestr, DEFAULT_REQUEST_TIME_SIZE,
                         "%04d-%02d-%02dT%02d:%02d:%02d.%03d%c%02d%02d",
                         xt.tm_year+1900, xt.tm_mon + 1, xt.tm_mday,
                         xt.tm_hour, xt.tm_min, xt.tm_sec, (int)apr_time_msec(request_time),
                         sign, timz / (60*60), (timz % (60*60)) / 60);
            msgpack_pack_ascii_string(mp_obj, r, timestr);
            break;
        }
        case ABS_SEC:
            mp_obj->type = MSGPACK_OBJECT_NEGATIVE_INTEGER;
            mp_obj->via.i64 = apr_time_sec(request_time);
            break;
        case ABS_MSEC:
            mp_obj->type = MSGPACK_OBJECT_NEGATIVE_INTEGER;
            mp_obj->via.i64 = apr_time_as_msec(request_time);
            break;
        case ABS_USEC:
            mp_obj->type = MSGPACK_OBJECT_NEGATIVE_INTEGER;
            mp_obj->via.i64 = request_time;
            break;
        case ABS_MSEC_FRAC:
            mp_obj->type = MSGPACK_OBJECT_POSITIVE_INTEGER;
            mp_obj->via.u64 = apr_time_msec(request_time);
            break;
        case ABS_USEC_FRAC:
            mp_obj->type = MSGPACK_OBJECT_POSITIVE_INTEGER;
            mp_obj->via.u64 = apr_time_usec(request_time);
            break;
    }
}

//%...T:  the time taken to serve the request, in seconds.
static void log_request_duration(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    apr_time_t duration = apr_time_sec(get_request_end_time(r) - r->request_time);
    mp_obj->type = MSGPACK_OBJECT_POSITIVE_INTEGER;
    mp_obj->via.u64 = duration;
}

//%...D:  the time taken to serve the request, in micro seconds.
static void log_request_duration_microseconds(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    apr_time_t duration = get_request_end_time(r) - r->request_time;
    mp_obj->type = MSGPACK_OBJECT_POSITIVE_INTEGER;
    mp_obj->via.u64 = duration;
}

//%...u:  remote user (from auth; may be bogus if return status (%s) is 401)
static void log_remote_user(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    msgpack_pack_encoded_string(mp_obj, r, info, r->user);
}

//%...U:  the URL path requested.
static void log_request_uri(msgpack_object *mp_obj, request_rec *r, log_entry_info_t *info)
{
    msgpack_pack_encoded_string(mp_obj, r, info, r->uri);
}

//%...v:  the configured name of the server (i.e. which virtual host?)
/* These next two routines use the canonical name:port so that log
 * parsers don't need to duplicate all the vhost parsing crud.
 */
static void log_virtual_host(msgpack_object *mp_obj, request_rec *r, log_entry_info_t* info)
{
    msgpack_pack_encoded_string(mp_obj, r, info, r->server->server_hostname);
}

//%...V:  the server name according to the UseCanonicalName setting
/* This respects the setting of UseCanonicalName so that
 * the dynamic mass virtual hosting trick works better.
 */
static void log_server_name(msgpack_object *mp_obj, request_rec *r, log_entry_info_t* info)
{
    msgpack_pack_encoded_string(mp_obj, r, info, ap_get_server_name(r));
}

//%...m:  the request method
static void log_request_method(msgpack_object *mp_obj, request_rec *r, log_entry_info_t* info)
{
    msgpack_pack_ascii_string(mp_obj, r, r->method);
}

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
//%...L:  the request log ID from the error log (or '-' if nothing has been logged to the error log for this request). Look for the matching error log line to see what request caused what error.
static void log_log_id(msgpack_object *mp_obj, request_rec *r, log_entry_info_t* info)
{
    const char *a = info->param;

    const char *log_id;

    if (a && !strcmp(a, "real")) {
        log_id = r->connection->log_id ? r->connection->log_id : NULL;
    }
    else {
        log_id = r->log_id ? r->log_id : NULL;
    }

    if (log_id != NULL) {
        msgpack_pack_ascii_string(mp_obj, r, log_id);
    }
}
#endif

//%...H:  the request protocol
static void log_request_protocol(msgpack_object *mp_obj, request_rec *r, log_entry_info_t* info)
{
    msgpack_pack_ascii_string(mp_obj, r, r->protocol);
}

//%...q:  the query string prepended by "?", or empty if no query string
static void log_request_query(msgpack_object *mp_obj, request_rec *r, log_entry_info_t* info)
{
    msgpack_pack_ascii_string(mp_obj, r, r->args);
}

//%...X:  Status of the connection.
//        'X' = connection aborted before the response completed.
//        '+' = connection may be kept alive after the response is sent.
//        '-' = connection will be closed after the response is sent.
//        (This directive was %...c in late versions of Apache 1.3, but
//         this conflicted with the historical ssl %...{var}c syntax.)
static void log_connection_status(msgpack_object *mp_obj, request_rec *r, log_entry_info_t* info)
{
    const char *status;

    if (r->connection->aborted)
        status = "X";
    else if (r->connection->keepalive == AP_CONN_KEEPALIVE &&
             (!r->server->keep_alive_max ||
              (r->server->keep_alive_max - r->connection->keepalives) > 0)) {
                 status = "+";
             }
    else {
        status = "-";
    }
    msgpack_pack_ascii_string(mp_obj, r, status);
}

//%...x:  SSL vars
static void log_ssl_var(msgpack_object *mp_obj, request_rec *r, log_entry_info_t* info)
{
    if (ssl_var_lookup == NULL) {
        return;
    }

    const char *a = info->param;

    char *result = ssl_var_lookup(r->pool, r->server, r->connection, r, (char *)a);
    if (result != NULL && strlen(result) != 0) {
        msgpack_pack_ascii_string(mp_obj, r, result);
    }
}

//custom function
static void log_hostname(msgpack_object *mp_obj, request_rec *r, log_entry_info_t* info)
{
    char hostname[APRMAXHOSTLEN + 1];
    apr_gethostname(hostname, APRMAXHOSTLEN, r->pool);
    msgpack_pack_ascii_string(mp_obj, r, hostname);
}

/*****
* Directives management
*/

static const char *set_log_server_host(cmd_parms *cmd, void *cfg, const char *arg)
{
    config.host = arg;
    return NULL;
}

static const char *set_log_server_port(cmd_parms *cmd, void *cfg, const char *arg)
{
    config.port = atoi(arg);
    return NULL;
}

static const char *set_log_encoding(cmd_parms *cmd, void *cfg, const char *arg)
{
    config.encoding = arg;
    return NULL;
}

static bool resolve_pack(log_entry_info_t *entry_info, const char *entry_name) {
    
    if (strcasecmp(entry_name, "request_time") == 0) {
        entry_info->pack_entry = log_request_time;
    }
    else if (strcasecmp(entry_name, "protocol") == 0) {
        entry_info->pack_entry = log_request_protocol;
    }
    else if (strcasecmp(entry_name, "bytes_sent") == 0) {
        entry_info->pack_entry = log_bytes_sent;
    }
    else if (strcasecmp(entry_name, "remote_port") == 0) {
        entry_info->pack_entry = log_remote_port;
    }
    else if (strcasecmp(entry_name, "cookie") == 0) {
        entry_info->pack_entry = log_cookie;
    }
    else if (strcasecmp(entry_name, "env") == 0) {
        entry_info->pack_entry = log_env_var;
    }
    else if (strcasecmp(entry_name, "request_file") == 0) {
        entry_info->pack_entry = log_request_file;
    }
    else if (strcasecmp(entry_name, "remote_host") == 0) {
        entry_info->pack_entry = log_remote_host;
    }
    else if (strcasecmp(entry_name, "remote_address") == 0) {
        entry_info->pack_entry = log_remote_address;
    }
    else if (strcasecmp(entry_name, "local_address") == 0) {
        entry_info->pack_entry = log_local_address;
    }
    else if (strcasecmp(entry_name, "header_in") == 0) {
        entry_info->pack_entry = log_header_in;
    }
    else if (strcasecmp(entry_name, "header_out") == 0) {
        entry_info->pack_entry = log_header_out;
    }
    else if (strcasecmp(entry_name, "requests_on_connection") == 0) {
        entry_info->pack_entry = log_requests_on_connection;
    }
    else if (strcasecmp(entry_name, "remote_logname") == 0) {
        entry_info->pack_entry = log_remote_logname;
    }
    else if (strcasecmp(entry_name, "note") == 0) {
        entry_info->pack_entry = log_note;
    }
    else if (strcasecmp(entry_name, "server_port") == 0) {
        entry_info->pack_entry = log_server_port;
    }
    else if (strcasecmp(entry_name, "pid_tid") == 0) {
        entry_info->pack_entry = log_pid_tid;
    }
    else if (strcasecmp(entry_name, "status") == 0) {
        entry_info->pack_entry = log_status;
        entry_info->final = FALSE;
    }
    else if (strcasecmp(entry_name, "request_time") == 0) {
        entry_info->pack_entry = log_request_time;
    }
    else if (strcasecmp(entry_name, "request_duration") == 0) {
        entry_info->pack_entry = log_request_duration;
        entry_info->final = FALSE;
    }
    else if (strcasecmp(entry_name, "request_duration_microseconds") == 0) {
        entry_info->pack_entry = log_request_duration_microseconds;
        entry_info->final = FALSE;
    }
    else if (strcasecmp(entry_name, "remote_user") == 0) {
        entry_info->pack_entry = log_remote_user;
        entry_info->final = FALSE;
    }
    else if (strcasecmp(entry_name, "request_uri") == 0) {
        entry_info->pack_entry = log_request_uri;
    }
    else if (strcasecmp(entry_name, "virtual_host") == 0) {
        entry_info->pack_entry = log_virtual_host;
    }
    else if (strcasecmp(entry_name, "server_name") == 0) {
        entry_info->pack_entry = log_server_name;
    }
    else if (strcasecmp(entry_name, "request_method") == 0) {
        entry_info->pack_entry = log_request_method;
    }
    else if (strcasecmp(entry_name, "request_protocol") == 0) {
        entry_info->pack_entry = log_request_protocol;
    }
    else if (strcasecmp(entry_name, "request_query") == 0) {
        entry_info->pack_entry = log_request_query;
    }
    else if (strcasecmp(entry_name, "connection_status") == 0) {
        entry_info->pack_entry = log_connection_status;
    }
    else if (strcasecmp(entry_name, "hostname") == 0) {
        entry_info->pack_entry = log_hostname;
#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    }
    else if (strcasecmp(entry_name, "log_id") == 0) {
        entry_info->pack_entry = log_log_id;
    }
    else if (strcasecmp(entry_name, "handler") == 0) {
        entry_info->pack_entry = log_handler;
#endif
    }
    else if (strcasecmp(entry_name, "ssl_var") == 0) {
        entry_info->pack_entry = log_ssl_var;
    } else {
        return false;
    }
    return true;
}

static const char *
add_log_entries(cmd_parms *cmd, void *dummy, const char *arg)
{
    if (config.entries == NULL) {
        config.entries = apr_table_make(cmd->pool, 10);
    }
    
    while (*arg) {
        log_entry_info_t *entry_info = apr_pcalloc(cmd->pool, sizeof(log_entry_info_t));
        entry_info->options = apr_table_make(cmd->pool, 0);
        entry_info->final = TRUE;

        char *entry_name = ap_getword_conf(cmd->pool, &arg);
        if (! resolve_pack(entry_info, entry_name)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
                         "log_net: unknown log entry %s", entry_name);
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                         "log_net: new log entry %s", entry_name);
        }
        
        apr_table_setn(config.entries, entry_name, (const char *)entry_info);
    }
    return NULL;
}

static const char *
add_log_entry(cmd_parms *cmd, void *dummy, const char *arg)
{
    if (config.entries == NULL) {
         config.entries = apr_table_make(cmd->pool, 10);
    }
    log_entry_info_t *entry_info = apr_pcalloc(cmd->pool, sizeof(log_entry_info_t));
    entry_info->options = apr_table_make(cmd->pool, 1);
    entry_info->final = TRUE;
    
    char *entry_name = ap_getword_conf(cmd->pool, &arg);
    if (entry_name == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
                     "log_net: empty log entry");
        return NULL;
    }

    if (! resolve_pack(entry_info, entry_name)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
                     "log_net: unknow log entry %s", entry_name);
        return NULL;
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                     "log_net: new log entry %s", entry_name);
    }

    bool first = true;
    while (*arg) {
        if (arg[0] == '#') {
            break;
        }
        char *word = ap_getword_conf(cmd->pool, &arg);
        char *val = strchr(word, '=');
        if (first && val == NULL) {
            entry_info->param = word;
            first = false;
            continue;
        }
        if (val != NULL) {
            *val++ = '\0';
        }
        // If the option is 'name', it overrides the name
        if (strcasecmp(word, "name") == 0) {
            entry_name = val;
        } else if (strcasecmp(word, "request") == 0) {
            if (strcasecmp(val, "final") == 0) {
                entry_info->final = TRUE;
            } else if (strcasecmp(val, "original") == 0) {
                entry_info->final = FALSE;
            } else {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
                             "log_net: unknow request choice %s for %s", val, entry_name);
                
            }
        } else {
            apr_table_setn(entry_info->options, word, val);
        }
    }
    apr_table_setn(config.entries, entry_name, (const char *)entry_info);
    return NULL;
}

static size_t make_msgpack(request_rec *r, void **message)
{
    // Ensure a good precision end time for request
    get_request_end_time(r);

    /* creates buffer and serializer instance. */
    msgpack_sbuffer *buffer = msgpack_sbuffer_new();
    msgpack_packer *pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
    
    const apr_array_header_t *elts = apr_table_elts(config.entries);
    
    const apr_table_entry_t *t_elt = (const apr_table_entry_t *)elts->elts;
    const apr_table_entry_t *t_end = t_elt + elts->nelts;

    // Resolve the requeste original and final
    request_rec *original_r = r;
    while (original_r->prev) {
        original_r = original_r->prev;
    }
    request_rec *final_r = r;
    while (final_r->next) {
        final_r = final_r->next;
    }

    msgpack_object mapping;
    mapping.type = MSGPACK_OBJECT_MAP;
    mapping.via.map.ptr = apr_palloc(r->pool, sizeof(msgpack_object_kv) * elts->nelts);
    mapping.via.map.size = 0;
    do {
        char *log_entry_name = (char *)t_elt->key;
        log_entry_info_t *log_entry_info = (log_entry_info_t *)t_elt->val;
        if (log_entry_info->pack_entry != NULL) {
            msgpack_object_kv *map_entry = &mapping.via.map.ptr[mapping.via.map.size];
            map_entry->val.type = MSGPACK_OBJECT_NIL;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "logging %s", log_entry_name);
            log_entry_info->pack_entry(&map_entry->val, log_entry_info->final ? final_r : original_r, log_entry_info);
            // Don't log empty data
            if (map_entry->val.type != MSGPACK_OBJECT_NIL) {
                msgpack_pack_ascii_string(&map_entry->key, r, log_entry_name);
                mapping.via.map.size++;
            }
        }
        ++t_elt;
    } while (t_elt < t_end);
    msgpack_pack_object(pk, mapping);
    size_t size = buffer->size;
    *message = (void *)apr_palloc(r->pool, size);
    if (*message != NULL) {
        memcpy(*message, buffer->data, size);
    } else {
        size = 0;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "memory allocation failed");
    }
    /* cleaning */
    msgpack_sbuffer_free(buffer);
    msgpack_packer_free(pk);
    return size;
}

static apr_status_t send_msg_udp(void *message, apr_size_t msg_size, request_rec *r)
{
    apr_status_t rv;
    if ((rv = apr_socket_sendto(udp_socket, server_addr, 0, message, &msg_size)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "log_net: send log message failed");
        return rv;
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "log_net: log packet sent %lu bytes", msg_size);
        return APR_SUCCESS;
    }
}

static apr_status_t send_udp_msgpack(request_rec *r)
{
    if (server_addr == NULL || udp_socket == NULL) {
        return APR_SUCCESS;
    }

    void *message;
    size_t msg_size = make_msgpack(r, &message);
    if (msg_size > 0) {
        return send_msg_udp(message, msg_size, r);
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "Generated empty message");
        return APR_SUCCESS;
    }
}

static int init_udp_socket(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    //Nothing configured, failed silently
    if (config.host == NULL && config.port == 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "log_net: destination not configured");
        return OK;
    }
    if ( config.host == NULL || config.port == 0) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, 0, s,
                     "log_net: network configuration incomplete");
        return !OK;
    }
    apr_status_t rv;
    server_addr = NULL;
    udp_socket = NULL;
    if ((rv = apr_sockaddr_info_get(&server_addr, config.host, APR_UNSPEC, config.port, APR_IPV4_ADDR_OK, p)) != APR_SUCCESS) {
         ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "log_net: apr_sockaddr_info_get(%s:%d) failed",
                     config.host, config.port);
        return !OK;
    }

    if ((rv = apr_socket_create(&udp_socket, APR_INET, SOCK_DGRAM, 0, p)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "log_net: apr_socket_create failed");
        return !OK;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "log_net: UPD socket will send to %s:%d", config.host, config.port);
    return OK;
}

static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);

    return init_udp_socket(p, plog, ptemp, s);
}

static int init_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp){
    bzero(&config, sizeof((config)));
    config.encoding = "UTF-8";

    return OK;
}

static const command_rec log_net_directives[] =
{
    AP_INIT_TAKE1("LognetHost", set_log_server_host, NULL, RSRC_CONF, "Hostname of the log server"),
    AP_INIT_TAKE1("LognetPort", set_log_server_port, NULL, RSRC_CONF, "Port for the log server"),
    AP_INIT_TAKE1("LognetEncoding", set_log_encoding, NULL, RSRC_CONF, "Encoding for output string"),
    AP_INIT_RAW_ARGS("LognetEntry", add_log_entry, NULL, RSRC_CONF, "Add a log entry"),
    AP_INIT_RAW_ARGS("LognetEntries", add_log_entries, NULL, RSRC_CONF, "Add many log entries"),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_log_transaction(send_udp_msgpack, NULL , NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(init_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

#if AP_MODULE_MAGIC_AT_LEAST(20100609,1)
AP_DECLARE_MODULE(log_net) =
#else
module AP_MODULE_DECLARE_DATA log_net_module =
#endif
{
    STANDARD20_MODULE_STUFF,
    NULL,               /* create per-dir config */
    NULL,               /* merge per-dir config */
    NULL,               /* server config */
    NULL,               /* merge server config */
    log_net_directives, /* command apr_table_t */
    register_hooks      /* register hooks */
};
