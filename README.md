mod_log_net
===========

An UDP logger for Apache.

It use [msgpack](http://msgpack.org) to send compact data.

Each UDP packet will send the informations for one hit, it's content are given using `LognetEntries` and `LognetEntry`.

# Configuration settings

Load it with `LoadModule log_net_module .../mod_log_net.so`

 * `LognetHost` Hostname of the log server
 * `LognetPort` Port for the log server
 * `LognetEncoding` Encoding for output string, default to 'UTF-8'
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
 * `cookie`:  The contents of the HTTP cookie given by the parameter. Same as `, %{FOOBAR}C`
 * `env_var`: The contents of the environment variable given by the parameter. Only version 0 cookies are fully supported. Same as %{FOOBAR}e.
 * `request_file`: Filename. Same as `%f`
 * `remote_host`: Remote host. Same as `%h`
 * `remote_address`: Remote IP-address. Same as `%a`
 * `local_address`: Local IP-address. Same as `%A`
 * `header_in`: The contents of header line(s) given by the parameter in the request sent to the client. Same as %{Foobar}i.
 * `requests_on_connection`: The umber of keepalive requests served over this connection. Same as %k
 * `remote_logname`: The remote logname (from identd, if supplied). Same as %l
 * `note`:  The contents of note "Foobar" from another module. Same as %{Foobar}n
 * `header_out`:  The contents of Foobar: header line(s) in the reply. Same as %...{Foobar}o
 * `server_port`:  The canonical port for the server. The parameter can be `canonical`, `local`, or `remote`. Same as `%p`.
 * `pid_tid`: The process ID of the child that serviced the request. Valid parameter can be `pid`, `tid`, and `hextid`. `hextid` requires APR 1.2.0 or higher. Default is `pid`. Same as %P
 * `status`: The query status. For requests that got internally redirected, this is status of the *original* request . Same as %s
 * `request_time`: The request start time, in ISO 8601 format, with microseconds precision. If the `format` option is given, it will be formatted using strftime(3)
 * `request_duration`: The time taken to serve the request, in seconds. Same as %T
 * `request_duration_microseconds`:  The time taken to serve the request, in micro seconds. Same as %D.
 * `remote_user`: The remote user (from auth; may be bogus if return status (%s) is 401). Same as %u.
 * `request_uri`: The URL path requested. Same as %U
 * `virtual_host`: The configured name of the server (i.e. which virtual host?). Same as %v.
 * `server_name`: The server name according to the UseCanonicalName setting. Same as %V.
 * `request_method`: The request method. Same as %m.
 * `request_protocol`: The request protocol. Same as %H.
 * `request_query`: The query string. Same as %q, but without the '?'.
 * `connection_status`:  Status of the connection. Same as %X.
 * `hostname`:  the real server name as read by apr_gethostname.

Msgpack is a typed format, so when is non existent, a null value will be returned, instead of '-' as in mod_log_config.

Simple entries can be added with LognetEntries:

     LognetEntries bytes_sent local_address request_file

For entries that need options, uses LognetEntry:

    LognetEntry header_in Host
    LognetEntry cookie id

# Options

 * `name`: it can be used to override the value name
 * `format`: the value will be formatted according to format, using printf rules. The format string must contains one and only one occurence of %s that will be substituted by the value.
 * `encoding`: the value is converted using iconv, the default encoding used is ASCII. Invalid characters are replaced with a '?'.

# Using it with logstash

Add in /etc/logstash/conf.d/ a file:

    input {
      udp {
        port  => 1516
        type  => httpdpack
        codec => msgpack
      }
    }
    