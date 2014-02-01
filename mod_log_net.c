#include <string.h>

#include "apr_hash.h"
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

#include <msgpack.h>

module AP_MODULE_DECLARE_DATA log_net_module;

typedef struct {
    const char   *host;
    apr_port_t    port;
    apr_array_header_t  *headers;
    apr_array_header_t  *cookies;
} log_net_config_t;

static log_net_config_t config;
static apr_socket_t   *udp_socket;
static apr_sockaddr_t *server_addr;

/*****
* Directives management
*/

const char *set_log_server_host(cmd_parms *cmd, void *cfg, const char *arg)
{
    config.host = arg;
    return NULL;
}

const char *set_log_server_port(cmd_parms *cmd, void *cfg, const char *arg)
{
    config.port = atoi(arg);
    return NULL;
}

const char *add_log_header(cmd_parms *cmd, void *cfg, const char *arg)
{
    if (config.headers == NULL) {
        config.headers = apr_array_make(cmd->pool, 0, sizeof(char *));
    }
    APR_ARRAY_PUSH(config.headers, const char *) = arg;
    return NULL;
}

const char *add_log_cookie(cmd_parms *cmd, void *cfg, const char *arg)
{
    if (config.cookies == NULL) {
        config.cookies = apr_array_make(cmd->pool, 0, sizeof(char *));
    }
    APR_ARRAY_PUSH(config.cookies, const char *) = arg;
    return NULL;
}

static const command_rec log_net_directives[] =
{
    AP_INIT_TAKE1("lognetHost", set_log_server_host, NULL, RSRC_CONF, "Hostname of the log server"),
    AP_INIT_TAKE1("lognetPort", set_log_server_port, NULL, RSRC_CONF, "Port for the log server"),
    AP_INIT_TAKE1("lognetHeader", add_log_header, NULL, RSRC_CONF, "Add an header to log"),
    AP_INIT_TAKE1("lognetCookies", add_log_cookie, NULL, RSRC_CONF, "Add an cookie to log"),
    { NULL }
};

static const char *get_cookie(request_rec *r, const char *cookie_name)
{
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
            if (name) {
                char *value = name + strlen(name) + 1;
                apr_collapse_spaces(name, name);

                if (!strcasecmp(name, cookie_name)) {
                    char *last;
                    value += strspn(value, " \t");  /* Move past leading WS */
                    last = value + strlen(value) - 1;
                    while (last >= value && apr_isspace(*last)) {
                       *last = '\0';
                       --last;
                    }

                    return ap_escape_logitem(r->pool, value);
                }
            }
            cookies = NULL;
        }
    }
    return NULL;
}

//Return the request time as an ISO8601 string
static const char *format_request_time(request_rec *r)
{
    apr_time_exp_t xt;
    ap_explode_recent_localtime(&xt, r->request_time);
    apr_size_t retcode;
    char tstr[MAX_STRING_LEN];
    apr_strftime(tstr, &retcode, sizeof(tstr), "%Y-%m-%dT%H:%M:%S%z", &xt);
    return apr_pstrdup(r->pool, tstr);
}

static void msgpack_pack_string(msgpack_packer* p, const char* buffer)
{
    int len = strlen(buffer);
	msgpack_pack_raw(p, len);
	msgpack_pack_raw_body(p, buffer, len);
}

static void msgpack_pack_key_string(msgpack_packer* p, const char* key, const char* value)
{
    msgpack_pack_string(p, key);
    if(value != NULL) {
        msgpack_pack_string(p, value);        
    } else {
        msgpack_pack_nil(p);
    }
}

static int make_msgpack(request_rec *r, void **message)
{
   /* creates buffer and serializer instance. */
    msgpack_sbuffer *buffer = msgpack_sbuffer_new();
    msgpack_packer *pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);

    int bytes_sent = 0;
    if(r->sent_bodyct) {
        bytes_sent = r->bytes_sent;
    }
    int with_header = config.headers!= NULL && config.headers->nelts > 0 ? 1 : 0;
    int with_cookies = config.cookies && config.cookies->nelts > 0 ? 1 : 0;
    msgpack_pack_map(pk, 7 + with_header + with_cookies);
    msgpack_pack_key_string(pk, "method", r->method);
    msgpack_pack_key_string(pk, "remote_ip", r->connection->remote_ip);
    msgpack_pack_key_string(pk, "vhost", r->server->server_hostname);
    msgpack_pack_key_string(pk, "@timestamp", format_request_time(r));
    msgpack_pack_string(pk, "status");msgpack_pack_int(pk, r->status);
    msgpack_pack_string(pk, "duration");msgpack_pack_double(pk, 1e-6 * (apr_time_now() - r->request_time));
    msgpack_pack_string(pk, "bytes_sent");msgpack_pack_int(pk, bytes_sent);
    //Log the headers
    if(with_header == 1) {
        msgpack_pack_string(pk, "headers");
        msgpack_pack_map(pk, config.headers->nelts);
        int i;
        for(i=0; i< config.headers->nelts; i++ ) {
            const char *header_name = APR_ARRAY_IDX(config.headers, i, char *);
            const char *header_value = apr_table_get(r->headers_in, header_name);
            msgpack_pack_key_string(pk, header_name, header_value);
        }
    }
    //Log the cookies
    if(with_cookies == 1) {
        msgpack_pack_string(pk, "cookies");
        msgpack_pack_map(pk, config.cookies->nelts);
        int i;
        for(i=0; i< config.cookies->nelts; i++ ) {
            const char *cookie_name = APR_ARRAY_IDX(config.cookies, i, char *);
            const char *cookie_value = get_cookie(r, cookie_name);
            msgpack_pack_key_string(pk, cookie_name, cookie_value);
        }
    }

    int size = buffer->size;
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
    if(server_addr == NULL || udp_socket == NULL) {
         ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                     "log_net: unable to send log message");
        return APR_SUCCESS;
    }
    
    if ((rv = apr_socket_sendto(udp_socket, server_addr, 0, message, &msg_size)) != APR_SUCCESS) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                     "log_net: send log message failed");
        return rv;
    }

    return APR_SUCCESS;
}

static apr_status_t send_udp_msgpack(request_rec *r)
{
    void *message;
    int msg_size = make_msgpack(r, &message);
    if (msg_size > 0) {
        return send_msg_udp(message, msg_size, r);
    }
    return APR_SUCCESS;
}

static int init_udp_socket(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
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

static void register_hooks(apr_pool_t *p)
{
    ap_hook_log_transaction(send_udp_msgpack, NULL , NULL, APR_HOOK_MIDDLE);
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

