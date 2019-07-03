#include <string.h>

#include <apr_hash.h>
#include "ap_config.h"
#include "ap_provider.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "apr_strings.h"
#include "util_time.h"
#include "apr_lib.h"

#include <errno.h>

#include <iconv.h>

#include <msgpack.h>

module AP_MODULE_DECLARE_DATA log_net_module;

typedef struct log_entry_info_t {
    void (*pack_entry)(msgpack_packer*, request_rec *, struct log_entry_info_t *);
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
static apr_socket_t   *udp_socket;
static apr_sockaddr_t *server_addr;

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
/*
 * log_request_state holds request specific log data that is not
 * part of the request_rec.
 */
typedef struct {
    apr_time_t request_end_time;
} log_request_state;
#endif

/*********
 * Resolver helpers
 */

static void msgpack_pack_string(msgpack_packer* p, const char* buffer)
{
    size_t len = strlen(buffer);
    msgpack_pack_str(p, len);
    msgpack_pack_str_body(p, buffer, len);
}

static void msgpack_pack_data_string(msgpack_packer* p, const char* buffer, log_entry_info_t *info, const request_rec *r)
{
    if(buffer == NULL) {
        msgpack_pack_nil(p);
    }
    else {
        char converted[MAX_STRING_LEN];
        char formatted[MAX_STRING_LEN];
        const char *send_buffer = buffer;
        const char *dst_encoding = NULL;
        if(info != NULL) {
            dst_encoding = apr_table_get(info->options, "encoding");
        }
        if(dst_encoding == NULL) {
            dst_encoding = "UTF-8";
        }
        // Don't convert if encoding are equals or converting from "real" ASCII (7 bits) to UTF-8
        if (strcmp(config.encoding, dst_encoding) != 0 &&
            !( strcmp(config.encoding, "ASCII") == 0  && strcmp(config.encoding, "UTF-8") == 0 )) {
            iconv_t converter = iconv_open(config.encoding, dst_encoding);
            if (converter == (iconv_t) -1) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
                              "iconv: invalid conversion from %s to %s", config.encoding, dst_encoding);
                msgpack_pack_nil(p);
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
            } while(done_converted != -1 && outbytesleft > 0 && inbytesleft > 0);
            *outcursor = '\0';
            iconv_close(converter);
            
            if(done_converted == -1) {
                msgpack_pack_nil(p);
                return;
            } else {
                
            }
            send_buffer = converted;
        }
        const char *format;
        if(info != NULL && (format = apr_table_get(info->options, "format"))) {
            snprintf(formatted, MAX_STRING_LEN, format, buffer);
            send_buffer = formatted;
        }
        size_t len = strlen(send_buffer);
        msgpack_pack_str(p, len);
        msgpack_pack_str_body(p, send_buffer, len);
    }
}

static void find_multiple_headers(msgpack_packer* packer,
                                  request_rec *r,
                                  const apr_table_t *table,
                                  const char *key)
{
    const apr_table_entry_t *t_end;
    struct sle {
        struct sle *next;
        const char *value;
        apr_size_t len;
    } *result_list, *rp;
    
    const apr_array_header_t *elts = apr_table_elts(table);
    
    if (!elts->nelts) {
        return;
    }
    
    const apr_table_entry_t *t_elt = (const apr_table_entry_t *)elts->elts;
    t_end = t_elt + elts->nelts;
    int count = 0;
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
        msgpack_pack_array(packer, count);
        rp = result_list;
        while (rp) {
            msgpack_pack_data_string(packer, rp->value, NULL, r);
            rp = rp->next;
        }
    }
    return;
}

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
static apr_time_t get_request_end_time(request_rec *r)
{
    log_request_state *state = (log_request_state *)ap_get_module_config(r->request_config,
                                                                         &log_net_module);
    if (!state) {
        state = apr_pcalloc(r->pool, sizeof(log_request_state));
        ap_set_module_config(r->request_config, &log_net_module, state);
    }
    if (state->request_end_time == 0) {
        state->request_end_time = apr_time_now();
    }
    return state->request_end_time;
}
#endif

/*********
 * Resolve the values
 */

//%...B:  bytes sent, excluding HTTP headers.
static void log_bytes_sent(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
    if (!r->sent_bodyct) {
        msgpack_pack_long(packer, 0);
    }
    else {
        msgpack_pack_long(packer, r->bytes_sent);
    }
}

//%...{FOOBAR}C:  The contents of the HTTP cookie FOOBAR
static void log_cookie(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
    const char *a = info->param;

    if (a == NULL) {
        msgpack_pack_nil(packer);
        return;
    }
    
    const char *cookies_entry;
    bool packed = false;
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
                    
                    msgpack_pack_data_string(packer, value, info, r);
                    packed = true;
                    break;
                }
            }
            /* Iterate the remaining tokens using apr_strtok(NULL, ...) */
            cookies = NULL;
        }
    }
    if(! packed) {
        msgpack_pack_nil(packer);
    }
}

//%...{FOOBAR}e:  The contents of the environment variable FOOBAR
static void log_env_var(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
    const char *a = info->param;

    if (a == NULL) {
        msgpack_pack_nil(packer);
        return;
    }

    const char *value = apr_table_get(r->subprocess_env, a);
    msgpack_pack_data_string(packer, value, info, r);
}

//%...f:  filename
static void log_request_file(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
    msgpack_pack_data_string(packer, r->filename, info, r);
}

//%...h:  remote host
static void log_remote_host(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
    const char *remote_host;
#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    const char *a = info->param;
    if (a != NULL && strcmp(a, "real") == 0) {
        remote_host = ap_get_remote_host(r->connection, r->per_dir_config,
                                         REMOTE_NAME, NULL);
    }
    else {
        remote_host = ap_get_remote_host(r->connection, r->per_dir_config,
                                         REMOTE_NAME, NULL);
        //remote_host = ap_get_useragent_host(r, REMOTE_NAME, NULL);
    }
#else
    remote_host = ap_get_remote_host(r->connection,
                                    r->per_dir_config,
                                     REMOTE_NAME, NULL);
#endif
    msgpack_pack_data_string(packer, remote_host, info, r);
}

//%...a:  remote IP-address
static void log_remote_address(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
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
    msgpack_pack_data_string(packer, remote_addr, info, r);
}

//%...A:  local IP-address
static void log_local_address(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
    msgpack_pack_data_string(packer, r->connection->local_ip, info, r);
}

//%...{Foobar}i:  The contents of Foobar: header line(s) in the request sent to the client.
static void log_header_in(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
    const char *a = info->param;

    if (a == NULL) {
        msgpack_pack_nil(packer);
        return;
    }

    const char *header = apr_table_get(r->headers_in, a);
    msgpack_pack_data_string(packer, header, info, r);
}

//%...k:  number of keepalive requests served over this connection
static void log_requests_on_connection(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
    int num = r->connection->keepalives ? r->connection->keepalives - 1 : 0;
    msgpack_pack_int(packer, num);
}

//%...l:  remote logname (from identd, if supplied)
static void log_remote_logname(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
    msgpack_pack_data_string(packer, ap_get_remote_logname(r), info, r);
}

//%...{Foobar}n:  The contents of note "Foobar" from another module.
static void log_note(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
    const char *a = info->param;

    if (a == NULL) {
        msgpack_pack_nil(packer);
        return;
    }
    msgpack_pack_data_string(packer, apr_table_get(r->notes, a), info, r);
}

//%...{Foobar}o:  The contents of Foobar: header line(s) in the reply.
static void log_header_out(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
    const char *a = info->param;

    if (a == NULL) {
        msgpack_pack_nil(packer);
        return;
    }
    const char *cp = NULL;
    
    if (!strcasecmp(a, "Content-type") && r->content_type) {
        cp = ap_field_noparam(r->pool, r->content_type);
        msgpack_pack_data_string(packer, cp, info, r);
    }
    else if (!strcasecmp(a, "Set-Cookie")) {
        find_multiple_headers(packer, r, r->headers_out, a);
    }
    else {
        cp = apr_table_get(r->headers_out, a);
        msgpack_pack_data_string(packer, cp, info, r);
    }
    
}

//%...p:  the canonical port for the server
//%...{format}p: the canonical port for the server, or the actual local or remote port
// This match canonical or local format, default to canonical
static void log_server_port(msgpack_packer* packer, request_rec *r, log_entry_info_t* info)
{
    const char *a = info->param;

    apr_port_t port = -1;
    
    if (a == NULL || *a == '\0' || strcasecmp(a, "canonical") == 0) {
        port = r->server->port ? r->server->port : ap_default_port(r);
    }
    else if (strcasecmp(a, "local") == 0) {
        port = r->connection->local_addr->port;
    }
    msgpack_pack_int(packer, port);
}

//%...p:  the canonical port for the server
//%...{format}p: the canonical port for the server, or the actual local or remote port
static void log_remote_port(msgpack_packer* packer, request_rec *r, log_entry_info_t* info)
{

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    apr_port_t port = r->useragent_addr->port;
#else
    apr_port_t port = r->connection->remote_addr->port;
#endif
    msgpack_pack_int(packer, port);
}

//%...P:  the process ID of the child that serviced the request.
//%...{format}P: the process ID or thread ID of the child/thread that serviced the request
static void log_pid_tid(msgpack_packer* packer, request_rec *r, log_entry_info_t* info)
{
    const char *a = info->param;

    const char * pid_tid = NULL;
    if (a == NULL || *a == '\0' || strcasecmp(a, "pid") == 0) {
        pid_tid = ap_append_pid(r->pool, "", "");
    }
    else if (strcasecmp(a, "tid") == 0 || strcasecmp(a, "hextid")== 0) {
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
        msgpack_pack_data_string(packer, pid_tid, info, r);
    } else {
        msgpack_pack_nil(packer);
    }
}

//%...s:  status.  For requests that got internally redirected, this is status of the *original* request --- %...>s for the last.
static void log_status(msgpack_packer* packer, request_rec *r, log_entry_info_t* info)
{
    msgpack_pack_int(packer, r->status);
}

//%...R:  The handler generating the response (if any).
static void log_handler(msgpack_packer* packer, request_rec *r, log_entry_info_t* info)
{
    msgpack_pack_data_string(packer, r->handler, info, r);
}

static const char *log_request_time_custom(request_rec *r, const char *a,
                                           apr_time_exp_t *xt)
{
    apr_size_t retcode;
    char tstr[MAX_STRING_LEN];
    apr_strftime(tstr, &retcode, sizeof(tstr), a, xt);
    return apr_pstrdup(r->pool, tstr);
}

#define DEFAULT_REQUEST_TIME_SIZE 32
typedef struct {
    unsigned t;
    char timestr[DEFAULT_REQUEST_TIME_SIZE];
    unsigned t_validate;
} cached_request_time;

#define TIME_FMT_CUSTOM          0
#define TIME_FMT_CLF             1
#define TIME_FMT_ABS_SEC         2
#define TIME_FMT_ABS_MSEC        3
#define TIME_FMT_ABS_USEC        4
#define TIME_FMT_ABS_MSEC_FRAC   5
#define TIME_FMT_ABS_USEC_FRAC   6

#define TIME_CACHE_SIZE 4
#define TIME_CACHE_MASK 3
static cached_request_time request_time_cache[TIME_CACHE_SIZE];

//%...t:  time, in common log format time format
//%...{format}t:  The time, in the form given by format, which should be in strftime(3) format.
static void log_request_time(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
    apr_time_t request_time;
#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    // Check info value, always called for @timestamp, but with NULL info
    const char *a = info != NULL ? info->param : NULL;
    if (a != NULL && strcmp(a, "end") == 0) {
        request_time = get_request_end_time(r);
    } else if (a == NULL || strcmp(a, "begin") == 0){
        request_time = r->request_time;
    } else {
        msgpack_pack_nil(packer);
        return;
    }
#else
    request_time = r->request_time;
#endif

    apr_time_exp_t xt;
    ap_explode_recent_localtime(&xt, request_time);
    const char *format = NULL;
    if (info != NULL) {
        format = apr_table_get(info->options, "format");
    }
    int fmt_type = TIME_FMT_CUSTOM;
    if (format == NULL) {
        fmt_type = TIME_FMT_CLF;
    } else if (strcmp(format, "sec") == 0) {
        fmt_type = TIME_FMT_ABS_SEC;
    } else if (strcmp(format, "msec") == 0) {
        fmt_type = TIME_FMT_ABS_MSEC;
    } else if (strcmp(format, "usec") == 0) {
        fmt_type = TIME_FMT_ABS_USEC;
    } else if (strcmp(format, "msec_frac") == 0) {
        fmt_type = TIME_FMT_ABS_MSEC_FRAC;
    } else if (strcmp(format, "usec_frac") == 0) {
        fmt_type = TIME_FMT_ABS_USEC_FRAC;
    }
    
    printf("%s %d\n", format, fmt_type);
    if (fmt_type >= TIME_FMT_ABS_SEC) {      /* Absolute (micro-/milli-)second time
                                              * or msec/usec fraction
                                              */
        char* buf = apr_palloc(r->pool, 20);
        switch (fmt_type) {
            case TIME_FMT_ABS_SEC:
                apr_snprintf(buf, 20, "%" APR_TIME_T_FMT, apr_time_sec(request_time));
                break;
            case TIME_FMT_ABS_MSEC:
                apr_snprintf(buf, 20, "%" APR_TIME_T_FMT, apr_time_as_msec(request_time));
                break;
            case TIME_FMT_ABS_USEC:
                apr_snprintf(buf, 20, "%" APR_TIME_T_FMT, request_time);
                break;
            case TIME_FMT_ABS_MSEC_FRAC:
                apr_snprintf(buf, 20, "%03" APR_TIME_T_FMT, apr_time_msec(request_time));
                break;
            case TIME_FMT_ABS_USEC_FRAC:
                apr_snprintf(buf, 20, "%06" APR_TIME_T_FMT, apr_time_usec(request_time));
                break;
            default:
                buf[0] = '\0';
        }
        if (strlen(buf) > 0) {
            msgpack_pack_string(packer, buf);
        } else {
            msgpack_pack_nil(packer);
        }
    }
    else if (fmt_type == TIME_FMT_CUSTOM) {  /* Custom format */
        /* The custom time formatting uses a very large temp buffer
         * on the stack.  To avoid using so much stack space in the
         * common case where we're not using a custom format, the code
         * for the custom format in a separate function.  (That's why
         * log_request_time_custom is not inlined right here.)
         */
        ap_explode_recent_localtime(&xt, request_time);
        msgpack_pack_string(packer, log_request_time_custom(r, format, &xt));
    }
    else {                                   /* CLF format */
        /* This code uses the same technique as ap_explode_recent_localtime():
         * optimistic caching with logic to detect and correct race conditions.
         * See the comments in server/util_time.c for more information.
         */
        cached_request_time* cached_time = apr_palloc(r->pool,
                                                      sizeof(*cached_time));
        unsigned t_seconds = (unsigned)apr_time_sec(request_time);
        unsigned i = t_seconds & TIME_CACHE_MASK;
        *cached_time = request_time_cache[i];
        if ((t_seconds != cached_time->t) ||
            (t_seconds != cached_time->t_validate)) {
            
            /* Invalid or old snapshot, so compute the proper time string
             * and store it in the cache
             */
            char sign;
            int timz;
            
            ap_explode_recent_localtime(&xt, request_time);
            timz = xt.tm_gmtoff;
            if (timz < 0) {
                timz = -timz;
                sign = '-';
            }
            else {
                sign = '+';
            }
            cached_time->t = t_seconds;
            //        snprintf(formatstr, MAX_STRING_LEN, "%s.%06d%s", "%Y-%m-%dT%H:%M:%S", xt.tm_usec, "%z");

            apr_snprintf(cached_time->timestr, DEFAULT_REQUEST_TIME_SIZE,
                         "%04d-%02d-%02dT%02d:%02d:%02d.%06d%c%.2d%.2d",
                         xt.tm_year+1900, xt.tm_mon + 1, xt.tm_mday,
                         xt.tm_hour, xt.tm_min, xt.tm_sec, xt.tm_usec,
                         sign, timz / (60*60), (timz % (60*60)) / 60);
            cached_time->t_validate = t_seconds;
            request_time_cache[i] = *cached_time;
        }
        printf("%s\n", cached_time->timestr);
        msgpack_pack_string(packer, cached_time->timestr);
    }

    //char tstr[MAX_STRING_LEN + 1];
    //apr_strftime(tstr, &retcode, MAX_STRING_LEN, format, &xt);
    //msgpack_pack_string(packer, tstr);
}

//%...T:  the time taken to serve the request, in seconds.
static void log_request_duration(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    apr_time_t duration = get_request_end_time(r) - r->request_time;
#else
    apr_time_t duration = apr_time_now() - r->request_time;
#endif
    msgpack_pack_long(packer, apr_time_sec(duration));
}

//%...D:  the time taken to serve the request, in micro seconds.
static void log_request_duration_microseconds(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    apr_time_t duration = get_request_end_time(r) - r->request_time;
#else
    apr_time_t duration = apr_time_now() - r->request_time;
#endif
    msgpack_pack_long(packer, duration);
}

//%...u:  remote user (from auth; may be bogus if return status (%s) is 401)
static void log_remote_user(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
    const char *rvalue = r->user;
    
    if (rvalue == NULL) {
        msgpack_pack_nil(packer);
    }
    else {
        msgpack_pack_data_string(packer, rvalue, info, r);
    }
    
}

//%...U:  the URL path requested.
static void log_request_uri(msgpack_packer* packer, request_rec *r, log_entry_info_t *info)
{
    msgpack_pack_data_string(packer, r->uri, info, r);
}

//%...v:  the configured name of the server (i.e. which virtual host?)
/* These next two routines use the canonical name:port so that log
 * parsers don't need to duplicate all the vhost parsing crud.
 */
static void log_virtual_host(msgpack_packer* packer, request_rec *r, log_entry_info_t* info)
{
    msgpack_pack_data_string(packer, r->server->server_hostname, info, r);
}

//%...V:  the server name according to the UseCanonicalName setting
/* This respects the setting of UseCanonicalName so that
 * the dynamic mass virtual hosting trick works better.
 */
static void log_server_name(msgpack_packer* packer, request_rec *r, log_entry_info_t* info)
{
    msgpack_pack_data_string(packer, ap_get_server_name(r), info, r);
}

//%...m:  the request method
static void log_request_method(msgpack_packer* packer, request_rec *r, log_entry_info_t* info)
{
    msgpack_pack_data_string(packer, r->method, info, r);
}

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
//%...L:  the request log ID from the error log (or '-' if nothing has been logged to the error log for this request). Look for the matching error log line to see what request caused what error.
static void log_log_id(msgpack_packer* packer, request_rec *r, log_entry_info_t* info)
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
        msgpack_pack_data_string(packer, log_id, info, r);
    } else {
        msgpack_pack_nil(packer);
    }
}
#endif

//%...H:  the request protocol
static void log_request_protocol(msgpack_packer* packer, request_rec *r, log_entry_info_t* info)
{
    msgpack_pack_data_string(packer, r->protocol, info, r);
}

//%...q:  the query string prepended by "?", or empty if no query string
static void log_request_query(msgpack_packer* packer, request_rec *r, log_entry_info_t* info)
{
    if (r->args) {
        msgpack_pack_data_string(packer, r->args, info, r);
    } else {
        msgpack_pack_nil(packer);
    }
}

//%...X:  Status of the connection.
//        'X' = connection aborted before the response completed.
//        '+' = connection may be kept alive after the response is sent.
//        '-' = connection will be closed after the response is sent.
//        (This directive was %...c in late versions of Apache 1.3, but
//         this conflicted with the historical ssl %...{var}c syntax.)
static void log_connection_status(msgpack_packer* packer, request_rec *r, log_entry_info_t* info)
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
    msgpack_pack_data_string(packer, status, info, r);
}

//custom function
static void log_hostname(msgpack_packer* packer, request_rec *r, log_entry_info_t* info)
{
    char hostname[APRMAXHOSTLEN + 1];
    apr_gethostname(hostname, APRMAXHOSTLEN, r->pool);
    msgpack_pack_data_string(packer, hostname, info, r);
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
    
    if(strcasecmp(entry_name, "request_time") == 0) {
        entry_info->pack_entry = log_request_time;
    }
    else if(strcasecmp(entry_name, "protocol") == 0) {
        entry_info->pack_entry = log_request_protocol;
    }
    else if(strcasecmp(entry_name, "bytes_sent") == 0) {
        entry_info->pack_entry = log_bytes_sent;
    }
    else if(strcasecmp(entry_name, "remote_port") == 0) {
        entry_info->pack_entry = log_remote_port;
    }
    else if(strcasecmp(entry_name, "cookie") == 0) {
        entry_info->pack_entry = log_cookie;
    }
    else if(strcasecmp(entry_name, "env") == 0) {
        entry_info->pack_entry = log_env_var;
    }
    else if(strcasecmp(entry_name, "request_file") == 0) {
        entry_info->pack_entry = log_request_file;
    }
    else if(strcasecmp(entry_name, "remote_host") == 0) {
        entry_info->pack_entry = log_remote_host;
    }
    else if(strcasecmp(entry_name, "remote_address") == 0) {
        entry_info->pack_entry = log_remote_address;
    }
    else if(strcasecmp(entry_name, "local_address") == 0) {
        entry_info->pack_entry = log_local_address;
    }
    else if(strcasecmp(entry_name, "header_in") == 0) {
        entry_info->pack_entry = log_header_in;
    }
    else if(strcasecmp(entry_name, "header_out") == 0) {
        entry_info->pack_entry = log_header_out;
    }
    else if(strcasecmp(entry_name, "requests_on_connection") == 0) {
        entry_info->pack_entry = log_requests_on_connection;
    }
    else if(strcasecmp(entry_name, "remote_logname") == 0) {
        entry_info->pack_entry = log_remote_logname;
    }
    else if(strcasecmp(entry_name, "note") == 0) {
        entry_info->pack_entry = log_note;
    }
    else if(strcasecmp(entry_name, "server_port") == 0) {
        entry_info->pack_entry = log_server_port;
    }
    else if(strcasecmp(entry_name, "pid_tid") == 0) {
        entry_info->pack_entry = log_pid_tid;
    }
    else if(strcasecmp(entry_name, "status") == 0) {
        entry_info->pack_entry = log_status;
        entry_info->final = FALSE;
    }
    else if(strcasecmp(entry_name, "request_time") == 0) {
        entry_info->pack_entry = log_request_time;
    }
    else if(strcasecmp(entry_name, "request_duration") == 0) {
        entry_info->pack_entry = log_request_duration;
        entry_info->final = FALSE;
    }
    else if(strcasecmp(entry_name, "request_duration_microseconds") == 0) {
        entry_info->pack_entry = log_request_duration_microseconds;
        entry_info->final = FALSE;
    }
    else if(strcasecmp(entry_name, "remote_user") == 0) {
        entry_info->pack_entry = log_remote_user;
        entry_info->final = FALSE;
    }
    else if(strcasecmp(entry_name, "request_uri") == 0) {
        entry_info->pack_entry = log_request_uri;
    }
    else if(strcasecmp(entry_name, "virtual_host") == 0) {
        entry_info->pack_entry = log_virtual_host;
    }
    else if(strcasecmp(entry_name, "server_name") == 0) {
        entry_info->pack_entry = log_server_name;
    }
    else if(strcasecmp(entry_name, "request_method") == 0) {
        entry_info->pack_entry = log_request_method;
    }
    else if(strcasecmp(entry_name, "request_protocol") == 0) {
        entry_info->pack_entry = log_request_protocol;
    }
    else if(strcasecmp(entry_name, "request_query") == 0) {
        entry_info->pack_entry = log_request_query;
    }
    else if(strcasecmp(entry_name, "connection_status") == 0) {
        entry_info->pack_entry = log_connection_status;
    }
    else if(strcasecmp(entry_name, "hostname") == 0) {
        entry_info->pack_entry = log_hostname;
#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    }
    else if(strcasecmp(entry_name, "log_id") == 0) {
        entry_info->pack_entry = log_log_id;
    }
    else if(strcasecmp(entry_name, "handler") == 0) {
        entry_info->pack_entry = log_handler;
#endif
    } else {
        return false;
    }
    return true;
}

static const char *
add_log_entries(cmd_parms *cmd, void *dummy, const char *arg)
{
    if(config.entries == NULL) {
        config.entries = apr_table_make(cmd->pool, 10);
    }
    
    while (*arg) {
        log_entry_info_t *entry_info = apr_pcalloc(cmd->pool, sizeof(log_entry_info_t));
        entry_info->options = apr_table_make(cmd->pool, 0);
        entry_info->final = TRUE;

        char *entry_name = ap_getword_conf(cmd->pool, &arg);
        if(! resolve_pack(entry_info, entry_name)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
                         "log_net: unknown log entry %s", entry_name);
        }
        
        apr_table_setn(config.entries, entry_name, (const char *)entry_info);
    }
    return NULL;
}

static const char *
add_log_entry(cmd_parms *cmd, void *dummy, const char *arg)
{
    if(config.entries == NULL) {
         config.entries = apr_table_make(cmd->pool, 10);
    }
    log_entry_info_t *entry_info = apr_pcalloc(cmd->pool, sizeof(log_entry_info_t));
    entry_info->options = apr_table_make(cmd->pool, 1);
    entry_info->final = TRUE;
    
    char *entry_name = ap_getword_conf(cmd->pool, &arg);
    if(entry_name == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
                     "log_net: empty log entry");
        return NULL;
    }
    
    if(! resolve_pack(entry_info, entry_name)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
                     "log_net: unknow log entry %s", entry_name);
        return NULL;
    }
    
    bool first = true;
    while (*arg) {
        if (arg[0] == '#') {
            break;
        }
        char *word = ap_getword_conf(cmd->pool, &arg);
        char *val = strchr(word, '=');
        if(first && val == NULL) {
            entry_info->param = word;
            first = false;
            continue;
        }
        if (val != NULL) {
            *val++ = '\0';
        }
        // If the option is 'name', it overrides the name
        if(strcasecmp(word, "name") == 0) {
            entry_name = val;
        } else if (strcasecmp(word, "request") == 0) {
            if(strcasecmp(val, "final") == 0) {
                entry_info->final = TRUE;
            } else if(strcasecmp(val, "original") == 0) {
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
    /* creates buffer and serializer instance. */
    msgpack_sbuffer *buffer = msgpack_sbuffer_new();
    msgpack_packer *pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);
    
    const apr_array_header_t *elts = apr_table_elts(config.entries);
    
    const apr_table_entry_t *t_elt = (const apr_table_entry_t *)elts->elts;
    const apr_table_entry_t *t_end = t_elt + elts->nelts;
    
    msgpack_pack_map(pk, 1 + elts->nelts);
    
    // Resolve the requeste original and final
    request_rec *original_r = r;
    while (original_r->prev) {
        original_r = original_r->prev;
    }
    request_rec *final_r = r;
    while (final_r->next) {
        final_r = final_r->next;
    }

    /* always log the request timestamp*/
    msgpack_pack_string(pk, "@timestamp"); log_request_time(pk, r, NULL);
    
    do {
        char *log_entry_name = (char *)t_elt->key;
        log_entry_info_t *log_entry_info = (log_entry_info_t *)t_elt->val;
        if(log_entry_info->pack_entry != NULL) {
            msgpack_pack_string(pk, log_entry_name);
            log_entry_info->pack_entry(pk, log_entry_info->final ? final_r : original_r, log_entry_info);
        }
        ++t_elt;
    } while (t_elt < t_end);

    size_t size = buffer->size;
    *message = (void *)apr_palloc(r->pool, size);
    if(*message != NULL) {
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
    }

    return APR_SUCCESS;
}

static apr_status_t send_udp_msgpack(request_rec *r)
{
    if(server_addr == NULL || udp_socket == NULL) {
        return APR_SUCCESS;
    }
    
    void *message;
    size_t msg_size = make_msgpack(r, &message);
    if (msg_size > 0) {
        send_msg_udp(message, msg_size, r);
    }
    return APR_SUCCESS;
}

static int init_udp_socket(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    //Nothing configured, failed silently
    if(config.host == NULL && config.port == 0) {
        return OK;
    }
    if(config.host == NULL || config.port == 0) {
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
    return OK;

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
    ap_hook_post_config(init_udp_socket, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA log_net_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,               /* create per-dir config */
    NULL,               /* merge per-dir config */
    NULL,               /* server config */
    NULL,               /* merge server config */
    log_net_directives,   /* command apr_table_t */
    register_hooks      /* register hooks */
};

