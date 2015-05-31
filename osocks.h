#ifndef OSOCKS_H
#define OSOCKS_H 1

#include <stdint.h>
#include <stdbool.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>

#define PROG_NAME "osocks"
#define PROG_VERSION "0.0.1"

#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
#endif
#ifndef MIN
# define MIN(a,b) (((a)<(b))?(a):(b))
#endif

/*
 *  SOCKS protocol related definitions
 *
 *  Names adapted from srelay-0.4.8b6
 */
#define SOCKS_VER5    0x5
#define SOCKS_PORT    1080

/*  SOCKSv5 address types */
#define S5ATYP_IPV4    1
#define S5ATYP_FQDN    3
#define S5ATYP_IPV6    4

/* SOCKSv5 authentication methods */
#define S5METHOD_NOAUTH     0
#define S5METHOD_GSSAPI     1
#define S5METHOD_USRPAS     2
#define S5METHOD_CHAP       3
#define S5METHOD_NOACC      0xff

static inline bool s5method_iana(uint8_t method)
{
	return method >= 0 && method <= 0x7f;
}

static inline bool s5method_assigned(uint8_t method)
{
	return method >= 0 && method <= 0x8;
}

static inline bool s5method_private(uint8_t method)
{
	return method >= 0x80 && method <= 0xfe;
}

/* SOCKSv5 request code */
#define S5CMD_CONN    1
#define S5CMD_BIND    2
#define S5CMD_UDPA    3

/* SOCKSv5 reply code */
#define S5REP_AGRANTED    0
#define S5REP_EGENERAL    1
#define S5REP_ENOTALOW    2
#define S5REP_ENETURCH    3
#define S5REP_EHOSURCH    4
#define S5REP_ECREFUSE    5
#define S5REP_ETTLEXPR    6
#define S5REP_EUNSUPRT    7
#define S5REP_EADRTYPE    8

static inline bool s5rep_unassigned(uint8_t rep)
{
	return rep >= 0x9 && rep <= 0xff;
}

enum sess_state {
	SESS_INIT,
	SESS_AUTH,
	SESS_REQ,
	SESS_CONNECTING,
	SESS_CONNECTED,
	SESS_DATA,
	SESS_END,
};

// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+
struct pkt_tcp0 {
	int					nbytes;
	uint8_t				ver;
	uint8_t				nmethod;
	uint32_t			methods_map[8];
};

// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+
struct pkt_tcp1 {
	uint8_t				ver;
	uint8_t				method;
};

/* binary format of SOCKSv5 address */
struct socks5_addr {
  uint8_t      atyp;
  union {
    uint8_t    ip4[4];
    struct {
      uint8_t  ip6[16];
    } _ip6;
    struct {
      uint8_t  _nlen;
      uint8_t  _name[255];
    } _fqdn;
  } _addr;
#define v4_addr   _addr.ip4
#define v6_addr   _addr._ip6.ip6
#define v6_scope  _addr._ip6.scope
#define fqdn_len  _addr._fqdn._nlen
#define fqdn      _addr._fqdn._name
};

// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
struct pkt_tcp2 {
	int					nbytes;
	uint8_t				ver;
	uint8_t				cmd;
	struct socks5_addr	addr;
	uint16_t			port;
};

struct socks_sess {
	enum sess_state			state;
	uint8_t					ver;
	uint8_t					method;
	struct pkt_tcp0			*pkt_tcp0;
	struct pkt_tcp2			*pkt_tcp2;
	struct ustream_fd		dfd;				/* downside: client <-> self */
	struct ustream_fd		ufd;				/* upside: self <-> target server */
	struct uloop_timeout	timeout_connect;	/* connection timeout */
	struct uloop_timeout	timeout_idle;		/* session idle timeout */
};
#define socks_sess_from_dfd(s)		container_of(s, struct socks_sess, dfd.stream)
#define socks_sess_from_ufd(s)		container_of(s, struct socks_sess, ufd.stream)

#endif
