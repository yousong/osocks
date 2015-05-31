
sizes="1K 4K 128K 512K 1M 4M 32M 128M 256M"

prepare_file() {
	local s

	for s in $sizes; do
		dd if=/dev/random of="data.$s.rand.bin" "bs=$s" count=1
	done
}

abing() {
	local s

	for s in $sizes; do
		ab -n 512 -c 64 -X localhost:8081 "http://127.0.0.1:8080/bar/data.$s.rand.bin"
	done
}

__privoxy() {
	cat > privoxy.conf <<EOF
listen-address 127.0.0.1:8081
forward-socks5 / localhost:7001 .
EOF

	privoxy --no-daemon privoxy.conf
}

__polipo() {
	cat >polipo.conf <<EOF
proxyAddress = "127.0.0.1"
proxyPort = 8081
allowedClients = "0.0.0.0/0"
proxyName = "polipo.example.org"
cacheIsShared = false
socksParentProxy = "localhost:7001"
socksProxyType = socks5
disableVia=false
censoredHeaders = from, accept-language
censorReferer = maybe

maxDiskCacheEntrySize = 0
uncachableFile = ^http://127.0.0.1:8080/$
EOF

	polipo -c polipo.conf
}

__nginx() {
	cat >>nginx.conf <<EOF
worker_process 4;
http {
	default_type application/octet-stream;
	sendfile on;
	access_log off;

	server {
		listen       8080;
		server_name  localhost;

		location /bar {
			alias /Users/yousong/Downloads;
			autoindex on;
		}
	}
}
EOF
}
