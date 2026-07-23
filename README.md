mod_log_net
===========

A UDP logger for Apache.

It uses [msgpack](http://msgpack.org) to send compact data.

Each UDP packet will send the information for every HTTP request, it's content are given using `LognetEntries` and `LognetEntry`.

# Configuration settings

Load it with `LoadModule log_net_module .../mod_log_net.so`

 * `LognetHost`: Hostname of the log server.
 * `LognetPort`: Port for the log server.
 * `LognetEntries`: Add many log entries, without options.
 * `LognetEntry`: Add a log entry, with optional parameters and options.

`LognetEntries` and `LognetEntry` can be used many times.

`LognetEntries` takes a sequence of value names to add in the log message:

    LognetEntries value_name [value_name ...]

`LognetEntry` takes a value name, followed by an optional parameter and options:

    LognetEntry value_name [parameter] [option[=value] ...]

This is a server level configuration.

# Installation

The module needs msgpack-c.

    ./configure --with-msgpack=/opt/local
    make
    make install

# Logged entries

The logged information are copied from `mod_log_config`. Generally any logged value matches a custom log entity and shares the same options.

 * `module_version`: The version of the log agent.
 * `bytes_sent`: Bytes sent, excluding HTTP headers. Same as `%B`.
 * `connection_status`: Status of the connection. Same as `%X`.
 * `constant`: A constant string value provided as a parameter.
 * `cookie`: The contents of the HTTP cookie given by the parameter. Same as `%{FOOBAR}C`.
 * `env`: The contents of the environment variable given by the parameter. Same as `%{FOOBAR}e`.
 * `handler`: The handler generating the response. Same as `%R`.
 * `header_in`: The contents of header line(s) given by the parameter in the request. Same as `%{Foobar}i`.
 * `header_out`: The contents of header line(s) in the reply. Same as `%{Foobar}o`.
 * `hostname`: The real server name as read by `apr_gethostname`.
 * `local_address`: Local IP-address. Same as `%A`.
 * `log_id`: The request log ID (or null if nothing has been logged). Same as `%L`.
 * `note`: The contents of note "Foobar" from another module. Same as `%{Foobar}n`.
 * `pid_tid`: The process or thread ID. Parameters: `pid`, `tid`, `hextid`. Default is `pid`. Same as `%P`.
 * `protocol`: The request protocol. Same as `%H`.
 * `remote_address`: Remote IP-address. The `real` argument ignores modifications by `mod_remoteip`. Same as `%a`.
 * `remote_host`: Remote host. The `real` argument ignores modifications by `mod_remoteip`. Same as `%h`.
 * `remote_logname`: The remote logname (from identd). Same as `%l`.
 * `remote_port`: The client's actual port. Same as `%{remote}p`.
 * `remote_user`: The remote user (if authenticated). Same as `%u`.
 * `request_duration`: The time taken to serve the request, in seconds. Same as `%T`.
 * `request_duration_microseconds`: The time taken to serve the request, in microseconds. Same as `%D`.
 * `request_file`: Filename. Same as `%f`.
 * `request_method`: The request method. Same as `%m`.
 * `request_protocol`: The request protocol. Same as `%H`.
 * `request_query`: The query string, without the '?'. Same as `%q`.
 * `request_time`: The request start time, with microseconds precision. Default is to use the [timestamp extension type](https://github.com/msgpack/msgpack/blob/master/spec.md#timestamp-extension-type).
    * `format` option allows using `strftime(3)` or Apache extensions (`sec`, `msec`, `usec`, `msec_frac`, `usec_frac`).
    * `iso8601` format produces strict ISO 8601 formatting with millisecond precision.
    * `end` argument logs the request end time.
    * Same as `%t`.
 * `request_uri`: The URL path requested. Same as `%U`.
 * `requests_on_connection`: Number of keepalive requests served over this connection. Same as `%k`.
 * `server_name`: The server name according to the `UseCanonicalName` setting. Same as `%V`.
 * `server_port`: The canonical port for the server. Parameters: `canonical`, `local`. Default is `canonical`. Same as `%p`.
 * `server_version`: The server version (matches `service.version` in ECS).
 * `ssl_var`: Variables from `mod_ssl` (if loaded). Same as `%x`.
 * `status`: The response status. For internal redirects, this is the status of the *original* request. Same as `%s`.
 * `virtual_host`: The configured name of the server (Virtual Host). Same as `%v`.

Msgpack is a typed format, so when a value is non-existent, a `null` will be returned instead of '-' (usual `mod_log_config` behavior).

Simple entries can be added with `LognetEntries`:

     LognetEntries bytes_sent local_address request_file

For entries that need options, use `LognetEntry`:

    LognetEntry header_in Host
    LognetEntry cookie id
    LognetEntry constant my_value name=my_constant

# Options

 * `name`: Used to override the key name in the output message.
 * `format`: Formats the value using `printf` rules. Must contain exactly one `%s`.
 * `request`: Extract information from original or final request in case of internal redirection (similar to `<` and `>`). By default, `status`, `remote_user`, `request_duration` and `request_duration_microseconds` use the original request, others use the final.

# Examples

```apache
<IfModule !log_net_module>
  LoadModule log_net_module    /usr/lib64/httpd/modules/mod_log_net.so
</IfModule>

LognetHost logger
LognetPort 1516
LognetEntries virtual_host bytes_sent request_query request_method remote_host local_address remote_user log_id handler
LognetEntry header_in Host name=host_header
LognetEntry header_in User-agent name=user_agent
LognetEntry header_in Referer name=referrer
LognetEntry hostname name=servername
LognetEntry env instance name=instance
LognetEntry status request=final
LognetEntry request_uri request=original
LognetEntry request_time end name=request_time_end
LognetEntry request_time begin name=request_time_begin
LognetEntry request_time format=sec name=request_time_sec
LognetEntry request_time format=msec name=request_time_msec
LognetEntry request_time format=usec name=request_time_usec
LognetEntry request_time format=msec_frac name=request_time_msec_frac
LognetEntry request_time format=usec_frac name=request_time_usec_frac
LognetEntry request_time format=%Y name=request_time_custom
LognetEntry request_duration_microseconds
LognetEntry server_port canonical name=server_port_canonical
LognetEntry server_port local name=server_port_local
LognetEntry server_port name=server_port
LognetEntry remote_port
LognetEntry remote_address real name=remote_address_real
LognetEntry remote_address name=remote_address_client
```

# Using with Logstash

Create a file in `/etc/logstash/conf.d/`:

    input {
      udp {
        port  => 1516
        type  => httpdpack
        codec => msgpack
      }
    }
