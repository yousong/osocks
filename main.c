#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <pwd.h>			/* struct passwd, getpwnam() */

#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/usock.h>
#include <libubox/utils.h>
#include <libubox/ulog.h>

#include "osocks.h"

#define OSOCKS_BUFLEN 4096
#define OSOCKS_TCP_TIMEOUT_CONNECT 8000
#define OSOCKS_TCP_TIMEOUT_IDLE 64000

struct uloop_fd self;
int timeout_connect = OSOCKS_TCP_TIMEOUT_CONNECT;
int timeout_idle = OSOCKS_TCP_TIMEOUT_IDLE;
int osocks_sess_num = 0;
int osocks_sess_num_max = -1;

static int ufd_init(struct socks_sess *sess);
static int self_init(const char *addr, const char *port);
static void toss_sess(struct socks_sess *sess);

static void ufd_dfd_read_cb(struct ustream *s, int bytes);
static void ufd_dfd_write_cb(struct ustream *s, int bytes);
static void ufd_dfd_state_cb(struct ustream *s);
static void ufd_ufd_read_cb(struct ustream *s, int bytes);
static void ufd_ufd_write_cb(struct ustream *s, int bytes);
static void ufd_ufd_state_cb(struct ustream *s);

#define ulog_err ULOG_ERR
#define ulog_info ULOG_INFO
#define ulog_warn ULOG_WARN
#define ulog_debug(fmt, ...) ulog(LOG_DEBUG, fmt, ## __VA_ARGS__)

static void sess_idle_timeout_cb(struct uloop_timeout *timeout)
{
	struct socks_sess *sess = container_of(timeout, struct socks_sess, timeout_idle);

	ulog_warn("session idle timeout\n");
	toss_sess(sess);
}

static void cb_self(struct uloop_fd *fd, unsigned int events)
{
	struct socks_sess *sess;
	struct pkt_tcp0 *tcp0;
	struct pkt_tcp2 *tcp2;
	int cfd;
	struct sockaddr_storage addr;
	socklen_t sl = sizeof(addr);

	cfd = accept(fd->fd, (struct sockaddr *)&addr, &sl);
	if (osocks_sess_num_max > 0 && osocks_sess_num >= osocks_sess_num_max) {
		ulog_warn("session num limit reached\n");
		close(cfd);
		return;
	}

	// FIXME make pkt_tcpN recyclable
	sess = (struct socks_sess *)calloc_a(sizeof(*sess),
			&tcp0, sizeof(*tcp0),
			&tcp2, sizeof(*tcp2));
	if (!sess) {
		ulog_err("out of memory");
		close(cfd);
		return;
	}
	sess->pkt_tcp0 = tcp0;
	sess->pkt_tcp2 = tcp2;
	sess->ufd.fd.fd = -1;
	/*
	 * buffer setting
	 *  - ufd -> dfd, big data
	 *  - control memory usage.
	 */
	sess->dfd.stream.w.buffer_len = OSOCKS_BUFLEN;
	sess->dfd.stream.w.min_buffers = 1;
	sess->dfd.stream.w.max_buffers = 4;
	sess->ufd.stream.r.buffer_len = OSOCKS_BUFLEN;
	sess->ufd.stream.r.min_buffers = 1;
	sess->ufd.stream.r.max_buffers = 4;

	sess->dfd.stream.notify_read = ufd_dfd_read_cb;
	sess->dfd.stream.notify_write = ufd_dfd_write_cb;
	sess->dfd.stream.notify_state = ufd_dfd_state_cb;
	sess->ufd.stream.notify_read = ufd_ufd_read_cb;
	sess->ufd.stream.notify_write = ufd_ufd_write_cb;
	sess->ufd.stream.notify_state = ufd_ufd_state_cb;
	ustream_fd_init(&sess->dfd, cfd);

	/* prepare a idle timeout */
	sess->timeout_idle.cb = sess_idle_timeout_cb;
	uloop_timeout_set(&sess->timeout_idle, timeout_idle);

	sess->state = SESS_INIT;
	osocks_sess_num += 1;
}

static void make_methods_map(uint32_t map[/*8*/], uint8_t methods[], int nmethod)
{
	int i;

	for (i = 0; i < nmethod; i++) {
		uint8_t m = methods[i];
		switch (m) {
			case S5METHOD_NOAUTH:
				map[m/8] |= 1 << (m % 8);
				break;
			case S5METHOD_NOACC:
				ulog_warn("NOACC in method request\n");
				break;
			case S5METHOD_GSSAPI:
			case S5METHOD_USRPAS:
			case S5METHOD_CHAP:
			default:
				ulog_debug("unsupported auth method: %x\n", m);
		}
	}
}

static inline bool method_is_set(uint32_t map[/*8*/], uint8_t method)
{
	uint32_t m = map[method / 8] & (1 << (method % 8));
	return !!m;
}

static uint8_t method_select(uint32_t map[/*8*/])
{
	if (method_is_set(map, S5METHOD_NOAUTH))
		return S5METHOD_NOAUTH;
	return S5METHOD_NOACC;
}

static int process_pkt_method(struct socks_sess *sess)
{
	struct ustream *s = &sess->dfd.stream;
	struct pkt_tcp0 *tcp0 = sess->pkt_tcp0;;
	int pending = ustream_pending_data(s, false);
	char buf[256];

	if (!tcp0->nbytes && pending < 2) {
		ulog_debug("not enough data\n");
		return 0;
	} else if (!tcp0->nbytes) {
		/* ver and nmethod */
		ustream_read(s, buf, 2);
		switch (buf[0]) {
			case SOCKS_VER5:
				break;
			default:
				ulog_warn("ver not supported\n");
				return -1;
		}
		sess->ver = buf[0];
		tcp0->ver = buf[0];
		tcp0->nmethod = buf[1];
		tcp0->nbytes = 2;
	}

	pending = ustream_pending_data(s, false);
	if (pending < tcp0->nmethod) {
		ulog_debug("not enough data\n");
		return 0;
	}
	/* methods id */
	ustream_read(s, buf, tcp0->nmethod);
	tcp0->nbytes += tcp0->nmethod;

	make_methods_map(tcp0->methods_map, (uint8_t *)buf, tcp0->nmethod);
	sess->method = method_select(tcp0->methods_map);
	buf[0] = SOCKS_VER5;
	buf[1] = sess->method;
	if (ustream_write(s, buf, 2, false) < 2)
		return -1;
	switch (sess->method) {
		case S5METHOD_NOAUTH:
			sess->state = SESS_REQ;
			return 0;
		case S5METHOD_NOACC:
		case S5METHOD_GSSAPI:
		case S5METHOD_USRPAS:
		case S5METHOD_CHAP:
		default:
			ulog_warn("no acceptable method\n");
			return -1;
	}
}

static int process_pkt_auth(struct socks_sess *sess)
{
	// nothing yet.
	return -1;
}

static int process_pkt_req(struct socks_sess *sess)
{
	struct ustream *s = &sess->dfd.stream;
	struct pkt_tcp2 *tcp2 = sess->pkt_tcp2;
	int pending = ustream_pending_data(s, false);
	char buf[256];
	int ret;

	if (!tcp2->nbytes && pending < 4) {
		ulog_debug("not enough data\n");
		return 0;
	} else if (!tcp2->nbytes) {
		/* ver and nmethod */
		ustream_read(s, buf, 4);
		if (buf[0] != sess->ver) {
			// ver not match
			ulog_warn("ver not match: %d %d\n", buf[0], sess->ver);
			return -1;
		}
		if (buf[2] != 0) {
			// RSV != 0
			ulog_warn("expecting 00 for RSV\n");
			return -1;
		}
		tcp2->ver = buf[0];
		tcp2->cmd = buf[1];
		tcp2->addr.atyp = buf[3];
		tcp2->nbytes += 4;
	}

	pending = ustream_pending_data(s, false);
	switch (tcp2->addr.atyp) {
		case S5ATYP_IPV4:
			if (pending < 4+2)
				return 0;
			ustream_read(s, (char *)tcp2->addr.v4_addr, 4);
			ustream_read(s, (char *)&tcp2->port, 2);
			ret = ufd_init(sess);
			break;
		case S5ATYP_FQDN:
			if (pending < 1)
				return 0;
			if (tcp2->nbytes == 4) {
				ustream_read(s, (char *)&tcp2->addr.fqdn_len, 1);
				tcp2->nbytes += 1;
			}

			pending = ustream_pending_data(s, false);
			if (pending < tcp2->addr.fqdn_len + 2)
				return 0;
			ustream_read(s, (char *)tcp2->addr.fqdn, tcp2->addr.fqdn_len);
			ustream_read(s, (char *)&tcp2->port, 2);
			ret = ufd_init(sess);
			break;
		case S5ATYP_IPV6:
			if (pending < 16+2)
				return 0;
			ustream_read(s, (char *)tcp2->addr.v6_addr, 16);
			ustream_read(s, (char *)&tcp2->port, 2);
			ret = ufd_init(sess);
			break;
		default:
			ulog_warn("unknown atyp\n");
			return -1;
	}

	return ret;
}

static int process_pkt_data(struct socks_sess *sess)
{
	struct ustream *s = &sess->dfd.stream;
	int pending;

	/* pipe data: dfd -> ufd */
	pending = ustream_pending_data(s, false);
	while (pending > 0) {
		int buflen;
		char *buf = ustream_get_read_buf(s, &buflen);
		bool more = pending > buflen;
		int wr = ustream_write(&sess->ufd.stream, buf, buflen, more);

		ustream_consume(s, wr);
		if (wr < buflen) {
			ustream_set_read_blocked(&sess->dfd.stream, true);
			break;
		}
		pending = ustream_pending_data(s, false);
	}
	return 0;
}

static void ufd_dfd_read_cb(struct ustream *s, int bytes)
{
	struct socks_sess *sess = socks_sess_from_dfd(s);
	enum sess_state state = sess->state;
	int ret;

	switch (state) {
		// move up the check manually
		case SESS_DATA:
			ret = process_pkt_data(sess);
			break;
		case SESS_INIT:
			ret = process_pkt_method(sess);
			break;
		case SESS_AUTH:
			ret = process_pkt_auth(sess);
			break;
		case SESS_REQ:
			ret = process_pkt_req(sess);
			break;
		case SESS_CONNECTING:
		case SESS_CONNECTED:
		default:
			return;
	}
	if (ret >= 0)
		uloop_timeout_set(&sess->timeout_idle, timeout_idle);
	else {
		ulog_debug("state: %d, failed processing pkt\n", sess->state);
		toss_sess(sess);
	}
}

static void ufd_dfd_write_cb(struct ustream *s, int bytes)
{
	struct socks_sess *sess = socks_sess_from_dfd(s);
	int pending = ustream_pending_data(&sess->ufd.stream, false);

	ustream_set_read_blocked(&sess->ufd.stream, false);
	if (pending > 0)
		ufd_ufd_read_cb(&sess->ufd.stream, pending);
	uloop_timeout_set(&sess->timeout_idle, timeout_idle);
}

static void ufd_ufd_read_cb(struct ustream *s, int bytes)
{
	struct socks_sess *sess = socks_sess_from_ufd(s);
	int pending;
	int written = 0;

	/* pipe data: ufd -> dfd */
	pending = ustream_pending_data(s, false);
	while (pending > 0) {
		int buflen;
		char *buf = ustream_get_read_buf(s, &buflen);
		bool more = pending > buflen;
		int wr = ustream_write(&sess->dfd.stream, buf, buflen, more);

		written += wr;
		ustream_consume(s, wr);
		if (wr < buflen) {
			ustream_set_read_blocked(s, true);
			break;
		}
		pending = ustream_pending_data(s, false);
	}
	if (written > 0)
		uloop_timeout_set(&sess->timeout_idle, timeout_idle);
}

static void ufd_ufd_write_cb(struct ustream *s, int bytes)
{
	struct socks_sess *sess = socks_sess_from_ufd(s);
	int pending = ustream_pending_data(&sess->dfd.stream, false);

	ustream_set_read_blocked(&sess->dfd.stream, false);
	if (pending > 0)
		ufd_dfd_read_cb(&sess->dfd.stream, pending);
	uloop_timeout_set(&sess->timeout_idle, timeout_idle);
}

static void toss_sess(struct socks_sess *sess)
{
	sess->state = SESS_END;

	ustream_free(&sess->dfd.stream);
	ustream_free(&sess->ufd.stream);
	close(sess->dfd.fd.fd);
	if (sess->ufd.fd.fd >= 0)
		close(sess->ufd.fd.fd);
	uloop_timeout_cancel(&sess->timeout_connect);
	uloop_timeout_cancel(&sess->timeout_idle);

	free(sess);
	osocks_sess_num -= 1;
}

static void ufd_ufd_state_cb(struct ustream *s)
{
	struct socks_sess *sess = socks_sess_from_ufd(s);

	if (s->eof || s->eof_write_done || s->write_error) {
		ulog_debug("ufd bye\n");
		toss_sess(sess);
	}
}

static void ufd_dfd_state_cb(struct ustream *s)
{
	struct socks_sess *sess = socks_sess_from_dfd(s);

	if (s->eof || s->eof_write_done || s->write_error) {
		ulog_debug("dfd bye\n");
		toss_sess(sess);
	}
}

static int ufd_so_error(struct socks_sess *sess)
{
	struct ustream_fd *ufd = &sess->ufd;
	struct uloop_fd *fd = &ufd->fd;
	int res, err;
	socklen_t sl = sizeof(err);

	res = getsockopt(fd->fd, SOL_SOCKET, SO_ERROR, &err, &sl);
	if (res)
		return errno;
	if (err)
		return err;
	return 0;
}

static int sess_write_rep(struct socks_sess *sess)
{
	struct ustream *s = &sess->dfd.stream;
	int fd = sess->ufd.fd.fd;
	struct sockaddr_storage ss;
	struct sockaddr_in *si;
	struct sockaddr_in6 *si6;
	socklen_t sl = sizeof(ss);
	char buf[32];
	int datalen;

	if (getsockname(fd, (struct sockaddr *)&ss, &sl) < 0) {
		ulog_err("getsockname(): %s\n", strerror(errno));
		return -1;
	}

	buf[0] = SOCKS_VER5;
	buf[1] = S5REP_AGRANTED;
	buf[2] = 0;
	switch (ss.ss_family) {
		case AF_INET:
			si = (struct sockaddr_in *)&ss;
			buf[3] = S5ATYP_IPV4;
			memcpy(&buf[4], &si->sin_addr, 4);
			memcpy(&buf[8], &si->sin_port, 2);
			datalen = 10;
			break;
		case AF_INET6:
			si6 = (struct sockaddr_in6 *)&ss;
			buf[3] = S5ATYP_IPV6;
			memcpy(&buf[4], &si6->sin6_addr, 16);
			memcpy(&buf[20], &si6->sin6_port, 2);
			datalen = 22;
			break;
		default:
			return -1;
	}

	sess->state = SESS_DATA;
	if (ustream_write(s, buf, datalen, false) < datalen)
		return -1;
	return 0;
}

static int ufd_fd_init(struct socks_sess *sess)
{
	if (ufd_so_error(sess)) {
		ulog_warn("not connected: %s\n", strerror(errno));
		return -1;
	}

	uloop_timeout_cancel(&sess->timeout_connect);
	ustream_fd_init(&sess->ufd, sess->ufd.fd.fd);
	sess->state = SESS_CONNECTED;

	return 0;
}

static void ufd_connected_cb(struct uloop_fd *fd, unsigned int events)
{
	struct socks_sess *sess = container_of(fd, struct socks_sess, ufd.fd);

	if (fd->error || fd->eof) {
		ulog_warn("connection failed\n");
		goto fail;
	}

	assert(events & ULOOP_WRITE);
	if (ufd_fd_init(sess) < 0) {
		goto fail;
	}

	if (sess_write_rep(sess) < 0) {
		ulog_warn("failed writing reply\n");
		goto fail;
	}
	return;

fail:
	toss_sess(sess);
}

static void ufd_timeout_cb(struct uloop_timeout *timeout)
{
	struct socks_sess *sess = container_of(timeout, struct socks_sess, timeout_connect);
	struct uloop_fd *fd = &sess->ufd.fd;

	ulog_warn("connection timeout\n");
	uloop_fd_delete(fd);
	toss_sess(sess);
}

static int ufd_init(struct socks_sess *sess)
{
	struct pkt_tcp2 *tcp2 = sess->pkt_tcp2;
	struct socks5_addr *paddr = &tcp2->addr;
	char buf[256];
	const char *addr;
	const char *port;
	int fd;

	port = usock_port(ntohs(tcp2->port));
	switch (paddr->atyp) {
		case S5ATYP_IPV4:
			addr = inet_ntop(AF_INET, paddr->v4_addr, buf, sizeof(buf));
			break;
		case S5ATYP_FQDN:
			snprintf(buf, sizeof(buf), "%*s", paddr->fqdn_len, (char *)paddr->fqdn);
			addr = buf;
			break;
		case S5ATYP_IPV6:
			addr = inet_ntop(AF_INET6, paddr->v6_addr, buf, sizeof(buf));
			break;
		default:
			ulog_warn("unknown addr type: %d\n", paddr->atyp);
			return -1;
	}
	if (!addr || !port) {
		ulog_warn("invalid address or port\n");
		return -1;
	}

	ulog_debug("connecting: %s:%s\n", addr, port);
	switch (sess->pkt_tcp2->cmd) {
		case S5CMD_CONN:
			fd = usock(USOCK_TCP | USOCK_NONBLOCK, addr, port);
			break;
		case S5CMD_BIND:
		case S5CMD_UDPA:
		default:
			ulog_warn("unkonwn cmd: %d\n", sess->pkt_tcp2->cmd);
			return -1;
	}
	if (fd < 0) {
		ulog_err("failed connecting: %s:%s\n",
				addr, port);
		return -1;
	}

	sess->state = SESS_CONNECTING;
	sess->ufd.fd.fd = fd;
	sess->ufd.fd.cb = ufd_connected_cb;
	sess->timeout_connect.cb = ufd_timeout_cb;
	uloop_fd_add(&sess->ufd.fd, ULOOP_WRITE | ULOOP_ERROR_CB);
	uloop_timeout_set(&sess->timeout_connect, timeout_connect);
	return 0;
}

static int self_init(const char *addr, const char *port)
{
	int fd;

	fd = usock(USOCK_TCP | USOCK_SERVER, addr, port);
	if (fd < 0) {
		ulog_err("failed binding\n");
		return -1;
	}

	self.fd = fd;
	self.cb = cb_self;
	uloop_fd_add(&self, ULOOP_READ | ULOOP_ERROR_CB);
	return 0;
}

static void be_nobody(void)
{
	struct passwd *pw;

	if (getuid() != 0)
		return;

	pw = getpwnam("nobody");
	if (!pw) {
		ulog_err("getpwnam(\"nobody\"): %s\n", strerror(errno));
		goto fail;
	}
	if (setgid(pw->pw_gid) < 0) {
		ulog_err("setgid: %s\n", strerror(errno));
		goto fail;
	}
	if (setuid(pw->pw_uid) < 0) {
		ulog_err("setuid: %s\n", strerror(errno));
		goto fail;
	}
	ulog_info("root privileges dropped\n");
	return;

fail:
	ulog_err("quit: failed dropping privileges\n");
	exit(1);
}

static void usage(void)
{
	fprintf(stderr,
"Usage: osocks [-l addr] [-p port] [-n num] [-I idle-timeout] [-T connect-timeout] [-svVh]\n"
"Options with default values in parenthesis:\n"
"  -l  listen address (0.0.0.0)\n"
"  -p  listen port (1080)\n"
"  -n  max number of live sessions (unlimited)\n"
"  -T  TCP connection timeout (8000ms)\n"
"  -I  session idle timeout (64000ms)\n"
"  -s  use syslog (false)\n"
"  -v  increase verbose level (LOG_INFO)\n"
"  -V  show version (" PROG_NAME " " PROG_VERSION ")\n"
"  -h  show help\n"
	);
}

static int arg_int(const char *optarg, const char *fmt, ...)
{
	char *endptr;
	int ret;
	va_list ap;

	ret = strtoul(optarg, &endptr, 10);
	if (*endptr || errno == ERANGE || errno == EINVAL) {
		char buf[256];

		va_start(ap, fmt);
		vsnprintf(buf, sizeof(buf), fmt, ap);
		va_end(ap);
		ulog_err("%s", buf);
		exit(1);
	}
	return ret;
}

int main(int argc, char *argv[])
{
	const char *listen_addr = "0.0.0.0";
	const char *listen_port = "1080";
	int use_syslog = false;
	int verbose = LOG_INFO;
	int opt;
	int ret;

	while ((opt = getopt(argc, argv, "l:p:n:I:T:svVh\n")) != -1) {
		switch (opt) {
			case 'l':
				listen_addr = optarg;
				break;
			case 'p':
				listen_port = optarg;
				break;
			case 'n':
				osocks_sess_num_max = arg_int(optarg, "bad session num max: %s\n", optarg);
				break;
			case 'T':
				timeout_connect = arg_int(optarg, "bad connect timeout: %s\n", optarg);
				break;
			case 'I':
				timeout_idle = arg_int(optarg, "bad idle timeout: %s\n", optarg);
				break;
			case 's':
				use_syslog = true;
				break;
			case 'v':
				verbose += 1;
				break;
			case 'V':
				fprintf(stderr, "%s %s\n", PROG_NAME, PROG_VERSION);
				return 0;
			case 'h':
				usage();
				return 0;
			default:
				ulog_err("unknown option: -%c\n", opt);
				usage();
				return -1;
		}
	}

	if (use_syslog)
		ulog_open(ULOG_SYSLOG, -1, PROG_NAME);
	else
		ulog_open(ULOG_STDIO, -1, PROG_NAME);
	ulog_threshold(verbose);

	uloop_init();

	ret = self_init(listen_addr, listen_port);
	if (ret < 0)
		goto out;

	be_nobody();

	uloop_run();

out:
	uloop_done();
	ulog_close();
	return ret;
}
