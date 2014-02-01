mod_log_net
===========

An UDP logger for Apache.

It use [msgpack](http://msgpack.org) to send compact data.

# Configuration settings

Load it with `LoadModule log_net_module .../mod_log_net.so`

 * `lognetHost` Hostname of the log server
 * `lognetPort` Port for the log server
 * `lognetHeader` Add an header to log
 * `lognetCookies` Add an cookie to log
 
`lognetHeader` and `lognetCookies` can be used many time, once for each header and cookie to log.

# Installation

    ./configure --with-msgpack=/opt/local
    make
    make install