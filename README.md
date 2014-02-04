mod_log_net
===========

An UDP logger for Apache.

It use [msgpack](http://msgpack.org) to send compact data.

Each UDP packet will send the informations for one hit, it's content are given using `LognetEntries` and `LognetEntry`.

# Configuration settings

Load it with `LoadModule log_net_module .../mod_log_net.so`

 * `LognetHost` Hostname of the log server
 * `LognetPort` Port for the log server
 * `LognetEntries` Add many log entries, without options
 * `LognetEntry` Add a log entry, with options

`LognetEntries` and `LognetEntry` can be used many time.

# Installation

    ./configure --with-msgpack=/opt/local
    make
    make install
    
# Logged entries

The logged information are copied from mod_log_config. Generaly any logged value match with a custom log entitie, and share options.

 * `bytes_sent`:  bytes sent, excluding HTTP headers, same as `%B`
 * `cookie`:  The contents of the HTTP cookie FOOBAR, same as `, %{FOOBAR}C`
 * `env_var`: The contents of the environment variable FOOBAR, same  %{FOOBAR}e
 * `request_file`: filename, same as  `%f`
 * `remote_host`:  remote host, same as `%h`
 * `remote_address`:  remote IP-address, same as `%a`
 * `local_address`:  local IP-address, same as `%A`
 * `header_in`:  The contents of Foobar: header line(s) in the request sent to the client. %...{Foobar}i
 * `requests_on_connection`:  number of keepalive requests served over this connection %...k
 * `remote_logname`:  remote logname (from identd, if supplied), same as `%l`
 * `note`:  The contents of note "Foobar" from another module. %...{Foobar}n
 * `header_out`:  The contents of Foobar: header line(s) in the reply. %...{Foobar}o
 * `server_port`:  the canonical port for the server, same as `%p`
     %...{format}p: the canonical port for the server, or the actual local or remote port
 * `pid_tid`:  the process ID of the child that serviced the request, same as %P
    %...{format}P: the process ID or thread ID of the child/thread that serviced the request
 * `status`:  status, same as %s
  %...s  For requests that got internally redirected, this is status of the *original* request --- %...>s for the last.
 * `request_time`:  time, in common log format time format
 //%...t
//%...{format}t:  The time, in the form given by format, which should be in strftime(3) format.
 * `request_duration`:  the time taken to serve the request, in seconds, same as %T
 * `request_duration_microseconds`:  the time taken to serve the request, in micro seconds, same as %D
 * `remote_user`:  remote user (from auth; may be bogus if return status (%s) is 401), same as %u
 * `request_uri`:  the URL path requested, same as %U
 * `virtual_host`:  the configured name of the server (i.e. which virtual host?), same as %v
 * `server_name`:  the server name according to the UseCanonicalName setting
 //%...V
 * `request_method`:  the request method, same as %m
 * `request_protocol`:  the request protocol, same as %H
 * `request_query`:  the query string, same as %q, but without the '?'
 * `connection_status`:  Status of the connection, same as %X

Simple entries can be added with LognetEntries:

     LognetEntries bytes_sent local_address request_file

For entries that need options, uses LognetEntry:

    LognetEntry header_in Host
    LognetEntry cookie id