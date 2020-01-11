mod_log_net
===========

An UDP logger for Apache.

It use [msgpack](http://msgpack.org) to send compact data.

Each UDP packet will send the informations for one hit, it's content are given using `LognetEntries` and `LognetEntry`.

# Configuration settings

Load it with `LoadModule log_net_module .../mod_log_net.so`

 * `LognetHost` Hostname of the log server
 * `LognetPort` Port for the log server
 * `LognetEncoding` Encoding for output string, default to 'UTF-8'. Any valid value for libiconv can be given.
 * `LognetEntries` Add many log entries, without options
 * `LognetEntry` Add a log entry, with options

`LognetEntries` and `LognetEntry` can be used many time.

A `LognetEntries` is a sequences of values name to add in the log message.

    LognetEntries value_name [value_name ...]

A `LognetEntry` is a value name, followed by a optionnal parameter and options:

    LognetEntry value_name [parameter] [option[=value] ...]]

This a server level configuration.

# Installation

The module needs msgpack-c and libiconv.

    ./configure --with-msgpack=/opt/local
    make
    make install
    
# Logged entries

The logged information are copied from mod_log_config. Generaly any logged value match with a custom log entitie, and share options.

 * `bytes_sent`: Bytes sent, excluding HTTP headers. Same as `%B`
 * `connection_status`:  Status of the connection. Same as %X.
 * `cookie`:  The contents of the HTTP cookie given by the parameter. Same as `%{FOOBAR}C`
 * `env_var`: The contents of the environment variable given by the parameter. Only version 0 cookies are fully supported. Same as %{FOOBAR}e.
 * `handler`: The handler generating the response (if any). Same as `%R`.
 * `header_in`: The contents of header line(s) given by the parameter in the request sent to the client. Same as %{Foobar}i.
 * `header_out`:  The contents of Foobar: header line(s) in the reply. Same as %...{Foobar}o.
 * `hostname`:  the real server name as read by apr_gethostname.
 * `local_address`: Local IP-address. Same as `%A`.
 * `log_id`: The request log ID from the error log (or null if nothing has been logged to the error log for this request). Look for the matching error log line to see what request caused what error. Same as `%L`.
 * `note`:  The contents of note "Foobar" from another module. Same as %{Foobar}n.
 * `pid_tid`: The process ID of the child that serviced the request. Valid parameter can be `pid`, `tid`, and `hextid`. `hextid` requires APR 1.2.0 or higher. Default is `pid`. Same as %P.
 * `requests_on_connection`: The umber of keepalive requests served over this connection. Same as %k.
 * `remote_logname`: The remote logname (from identd, if supplied). Same as %l.
 * `status`: The query status. For requests that got internally redirected, this is status of the *original* request . Same as %s
 * `request_time`: The request start time, with microseconds precision. The default is to use the [timestamp extension type](https://github.com/msgpack/msgpack/blob/master/spec.md#timestamp-extension-type). If the `format` option is given, it will be formatted using strftime(3) or specific Apache extensions like sec, usec and others. The custom format `iso8601` was added to use a strict ISO 8601 formatting, with milli-second precision. The numeric time stamp formatting like `sec` will be sent as numeric values. If `end` argument is given, it will log the request end time.Same as %t.
 * `request_duration`: The time taken to serve the request, in seconds. Same as %T.
 * `request_duration_microseconds`:  The time taken to serve the request, in micro seconds. Same as %D.
 * `request_file`: Filename. Same as `%f`.
 * `remote_address`: Remote IP-address. If `real` argument is given, always reports on the hostname of the underlying TCP connection and not any modifications to the remote hostname by modules like mod_remoteip. Same as `%a`.
 * `remote_host`: Remote host. If `real` argument is given, always reports on the hostname of the underlying TCP connection and not any modifications to the remote hostname by modules like mod_remoteip, only works with 2.4.19. Same as `%h`.
 * `remote_port`: The client's actual port. Same as `%{remote}p`.
 * `remote_user`: The remote user (from auth; may be bogus if return status (%s) is 401). Same as %u.
 * `request_uri`: The URL path requested. Same as %U.
 * `server_name`: The server name according to the UseCanonicalName setting. Same as %V.
 * `server_port`: The canonical port for the server. The parameter can be `canonical`, `local`, default to `canonical`. Same as `%p`.
 * `request_method`: The request method. Same as %m.
 * `request_protocol`: The request protocol. Same as %H.
 * `request_query`: The query string. Same as %q, but without the '?'.
 * `virtual_host`: The configured name of the server (i.e. which virtual host?). Same as %v.
 * `ssl_var`: log variables from mod_ssl when it's loaded, ignored otherwise. Same as %x.

Msgpack is a typed format, so when a value is non existent, a null will be returned, instead of '-' as in mod_log_config.

Simple entries can be added with LognetEntries:

     LognetEntries bytes_sent local_address request_file

For entries that need options, uses LognetEntry:

    LognetEntry header_in Host
    LognetEntry cookie id

# Options

 * `name`: it can be used to override the value name.
 * `format`: the value will be formatted according to format, using printf rules. The format string must contains one and only one occurence of %s that will be substituted by the value.
 * `encoding`: The input encoding for this value, the output encoding is the one given in the `LognetEncoding` configuration. The default value is ASCII. Invalid characters are replaced with a '?'.
 * `request`: Does the informations are extracted from the original or final request when it has been internally redirected. It works like '<' and '>'. By default, the entry  `status`, `remote_user`, `request_duration`, `request_duration_microseconds` look at the original request while all others look at the final request.
 
# Examples

```
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

# Using it with logstash

Add in /etc/logstash/conf.d/ a file:

    input {
      udp {
        port  => 1516
        type  => httpdpack
        codec => msgpack
      }
    }
    