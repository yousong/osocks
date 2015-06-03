`osocks` is a small dumb SOCKSv5 server doing epoll/kqueue with `libubox` of OpenWrt.

## Build and use

`osocks` can run on Mac OS X and Linux.  `libubox` is required dependency.

CMake is the build tool, so the following should emit out `osocks` binary.

	cmake . && make

The current synopsis is as follows.

	Usage: osocks [-l addr] [-p port] [-n num] [-I idle-timeout] [-T connect-timeout] [-svVh]
	Options with default values in parenthesis:
	  -l  listen address (0.0.0.0)
	  -p  listen port (1080)
	  -n  max number of live sessions (unlimited)
	  -T  TCP connection timeout (8000ms)
	  -I  session idle timeout (64000ms)
	  -s  use syslog (false)
	  -v  increase verbose level (LOG_INFO)
	  -V  show version (osocks 0.0.1)
	  -h  show help

It will run on `0.0.0.0:1080` by default if neither `-l` nor `-p` is present.

## FAQ

- Why not just using an existing implementation?

	- Dante
		- Big: too many processes, too sophisticated, resource hungry.
		- Commercial solution (?) with main (but not all) source code available.
		- Hard to track developement and debugging, tunning is pain.

	- Srelay
		- Not a fan of threading or forking model when on OpenWrt.

- Why making it, or why should I use it?

    - The code is small.
    - The memory usage is under control.
    - The speed is reasonably good.

- Are there plans to support GSSAPI, CHAP, and other authentication methods?

	Currently, no.  Reasons are as the following.

	- No such need for me at the moment.
	- Mac OS X only has USERNAME/PASSWORD for SOCKS proxy.
	- curl's USERNAME/PASSWORD is not CHAP.
	- GSSAPI is cryptic.

	But, good to know more and be complete.

## Ref

- SOCKS Protocol Version 5, https://tools.ietf.org/html/rfc1928
- SOCKS Methods, https://www.iana.org/assignments/socks-methods/socks-methods.xhtml
- Username/Password Authentication for SOCKS V5, http://tools.ietf.org/html/rfc1929
- GSS-API Authentication Method for SOCKS Version 5, https://tools.ietf.org/html/rfc1961
- Challenge-Handshake Authentication Protocol for SOCKS V5, https://tools.ietf.org/html/draft-ietf-aft-socks-chap-01
- Secure Sockets Layer for SOCKS Version 5, https://tools.ietf.org/html/draft-ietf-aft-socks-ssl-00

## Test

- ApacheBench only supports specifying HTTP proxy.
- Both Polipo and Privoxy supports using a SOCKS proxy for the upstream connection.
- But Polipo is a caching proxy.
- Privoxy is a non-caching proxy.
- So use ApacheBench and Privoxy on the same host should give reasonable result.

Run `osocks`

	./osocks -p 7001

Run `privoxy --no-daemon privoxy.conf` with `privoxy.conf` having the following content.

	listen-address 127.0.0.1:8081
	forward-socks5 / localhost:7001 .

Run ApacheBench to access generated test files served by local NGINX server.

	ab -n 1024 -c 64 -X localhost:8081 "http://127.0.0.1:8080/bar/data.1M.rand.bin"

See `tests.sh` for more details.

## TODO

- Test multiple osocks with `SO_REUSEPORT`
- What's the performance gain of single master, multiple workers?
- recycle pkt_tcp0, pkt_tcp2
- Reply to request with more explict error information.
- `-4`, `-6`
- USERNAME/PASSWORD, GSSAPI authentication support.

   > Compliant implementations MUST support GSSAPI and SHOULD support
   > USERNAME/PASSWORD authentication methods.

- CHAP authentication support.

   > compliant implementations MUST support HMAC-MD5.

- `libubox`, ustream-fd sendmsg().
- `libubox`, reproduce fd unfair and starvation.
- Statistics comparison with Dante.
