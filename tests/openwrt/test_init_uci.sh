#!/bin/sh
# Host-side test of the OpenWrt init script's UCI -> zroxy.conf generation.
# A tiny fake of /lib/functions.sh stands in for UCI; no OpenWrt is needed.
# Usage: test_init_uci.sh [path/to/zroxy.init] [path/to/zroxy-binary]
# When a binary is given, each generated file is also checked to parse.

HERE="$(cd "$(dirname "$0")" && pwd)"
INIT="${1:-$HERE/../../openwrt/files/zroxy.init}"
BIN="${2:-}"
WORK="$(mktemp -d)" || exit 1
trap 'rm -rf "$WORK"' EXIT
FAILS=0
NL='
'

# --- fake UCI --------------------------------------------------------------
logger() { printf '%s\n' "$*" >>"$WORK/log"; }
config_load() { :; }
config_get() { # VAR SECTION OPTION [DEFAULT]
	eval "_set=\${V_${2}__$3+x}"
	if [ -n "$_set" ]; then eval "$1=\$V_${2}__$3"; else eval "$1=\${4-}"; fi
}
config_get_bool() { # VAR SECTION OPTION [DEFAULT]
	config_get _b "$2" "$3" "${4-}"
	case "$_b" in 1|yes|on|true|enabled) _b=1 ;; *) _b=0 ;; esac
	eval "$1=$_b"
}
config_foreach() { # CALLBACK TYPE
	for _s in $SECTIONS; do
		case "$_s" in "$2":*) "$1" "${_s#*:}" ;; esac
	done
}
config_list_foreach() { # SECTION OPTION CALLBACK
	eval "_n=\${N_${1}__$2-0}"
	_i=1
	while [ "$_i" -le "$_n" ]; do
		eval "_v=\$L_${1}__$2__$_i"
		"$3" "$_v"
		_i=$((_i + 1))
	done
}

# fixture builders
reset() {
	for _v in $(set | sed -n 's/^\(\(V\|N\|L\)_[A-Za-z0-9_]*\)=.*/\1/p'); do
		unset "$_v"
	done
	SECTIONS=""
	: >"$WORK/log"
	ANON=0
}
sec() { # TYPE [NAME]
	if [ -n "$2" ]; then CUR="$2"; else ANON=$((ANON + 1)); CUR="cfg$ANON"; fi
	SECTIONS="$SECTIONS $1:$CUR"
}
opt() { eval "V_${CUR}__$1=\$2"; }
lst() {
	eval "_n=\${N_${CUR}__$1-0}"
	_n=$((_n + 1))
	eval "N_${CUR}__$1=$_n; L_${CUR}__$1__$_n=\$2"
}

# shellcheck disable=SC1090
. "$INIT" || { echo "cannot source $INIT"; exit 1; }
ZR_RUN_DIR="$WORK/run"

# --- harness ---------------------------------------------------------------
run_ok() { # NAME EXPECTED  (fixture already loaded)
	rm -rf "$WORK/run"
	if ! generate_conf "$ZR_RUN_DIR/zroxy.conf"; then
		echo "FAIL $1: generation failed: $(cat "$WORK/log")"
		FAILS=$((FAILS + 1)); return
	fi
	got="$(cat "$ZR_RUN_DIR/zroxy.conf")"
	want="# Generated from /etc/config/zroxy by the init script. Do not edit.${NL}$2"
	if [ "$got" != "$want" ]; then
		echo "FAIL $1: output differs"
		printf '%s\n' "$want" >"$WORK/want"; printf '%s\n' "$got" >"$WORK/got"
		diff "$WORK/want" "$WORK/got"
		FAILS=$((FAILS + 1)); return
	fi
	mode="$(stat -c '%a' "$ZR_RUN_DIR/zroxy.conf")"
	dmode="$(stat -c '%a' "$ZR_RUN_DIR")"
	if [ "$mode" != 600 ] || [ "$dmode" != 700 ]; then
		echo "FAIL $1: modes file=$mode dir=$dmode"; FAILS=$((FAILS + 1)); return
	fi
	if [ -n "$(ls -A "$ZR_RUN_DIR" | grep -v '^zroxy.conf$')" ]; then
		echo "FAIL $1: stray files in run dir"; FAILS=$((FAILS + 1)); return
	fi
	echo "ok   $1"
}
run_fail() { # NAME LOG-PATTERN
	rm -rf "$WORK/run"
	: >"$WORK/log"
	if generate_conf "$ZR_RUN_DIR/zroxy.conf"; then
		echo "FAIL $1: generation succeeded"; FAILS=$((FAILS + 1)); return
	fi
	if ! grep -q "$2" "$WORK/log"; then
		echo "FAIL $1: log lacks '$2': $(cat "$WORK/log")"; FAILS=$((FAILS + 1)); return
	fi
	if [ -e "$ZR_RUN_DIR/zroxy.conf" ] || [ -n "$(ls -A "$ZR_RUN_DIR")" ]; then
		echo "FAIL $1: left files behind"; FAILS=$((FAILS + 1)); return
	fi
	echo "ok   $1"
}

shipped_defaults() {
	reset
	sec zroxy main; opt enabled 0; opt jail 1
	lst listen 127.0.0.1:8443@443
	opt snitimeout 30; opt log 2
	sec dns dns; opt enabled 0; opt listen 127.0.0.1:5354
	sec route; opt enabled 1; opt server 9.9.9.9
	sec monitor monitor; opt enabled 0; opt listen 127.0.0.1:8123
}

# --- cases -----------------------------------------------------------------
shipped_defaults
run_ok defaults "LOG = 2
PORT = 127.0.0.1:8443@443
SNITIMEOUT = 30"

shipped_defaults
opt() { eval "V_${CUR}__$1=\$2"; }
CUR=main
opt white /etc/zroxy/whitelist.txt; opt openproxy 0; opt allowloopback yes
opt denyprivate 1; opt socks user@127.0.0.1:1080
opt socks_pass_file /etc/zroxy/socks.pass; opt sniidletimeout 120
opt user zroxy; opt group nogroup
lst listen 192.168.1.1:8443@443,8080@80
run_ok lan_whitelist_socks "LOG = 2
USER = zroxy
GROUP = nogroup
PORT = 127.0.0.1:8443@443
PORT = 192.168.1.1:8443@443,8080@80
SOCKS = user@127.0.0.1:1080
SOCKSPASSFILE = /etc/zroxy/socks.pass
SNITIMEOUT = 30
SNIIDLETIMEOUT = 120
ALLOWLOOPBACK = yes
DENYPRIVATE = yes
WHITE = /etc/zroxy/whitelist.txt
OPENPROXY = no"

reset
sec zroxy main; opt enabled 1; lst listen 127.0.0.1:8443@443; opt openproxy yes
sec dns dns; opt enabled 1; opt listen 127.0.0.1:5354
lst acl 192.168.1.0/24; lst acl 10.0.0.0/8
opt dsocks 127.0.0.1:1080; opt timeout 5; opt cache 512; opt ttl 60
opt rate 50; opt connections 8; opt snip 192.168.1.1
sec route; opt server 1.1.1.1:53; opt via 127.0.0.1:9050
sec route; opt server 192.168.1.1; opt via direct
sec route; opt enabled 0; opt server 8.8.8.8
sec route; opt server 9.9.9.9
sec monitor monitor; opt enabled 1; opt listen 127.0.0.1:8123
opt token_file /etc/zroxy/monitor.token; opt timeout 3
run_ok dns_routes_monitor "PORT = 127.0.0.1:8443@443
OPENPROXY = yes
LDNS = 127.0.0.1:5354
DNS = 1.1.1.1:53 via 127.0.0.1:9050
DNS = 192.168.1.1 via direct
DNS = 9.9.9.9
DSOCKS = 127.0.0.1:1080
DTIMEOUT = 5
SNIP = 192.168.1.1
DCACHE = 512
DTTL = 60
DACL = 192.168.1.0/24,10.0.0.0/8
DRATE = 50
DNSCONNECTIONS = 8
MONITOR = 127.0.0.1:8123
MONITORTOKENFILE = /etc/zroxy/monitor.token
MONITORTIMEOUT = 3"

# DNS disabled: no DNS keys even with routes and options set.
CUR=dns; opt enabled 0
CUR=monitor; opt enabled 0
run_ok dns_disabled "PORT = 127.0.0.1:8443@443
OPENPROXY = yes"

# newline / CR injection in any kind of value
shipped_defaults
CUR=main; opt white "/etc/zroxy/w.txt${NL}USER = root"
run_fail newline_in_option "line break"
shipped_defaults
CUR=main; lst listen "127.0.0.1:1@2${NL}SOCKS = evil:1"
run_fail newline_in_list "line break"
shipped_defaults
CUR=main; opt socks "$(printf 'a\rb')"
run_fail cr_in_option "line break"
shipped_defaults
CUR=dns; opt enabled 1; lst acl "10.0.0.0/8${NL}DSOCKS = x"
run_fail newline_in_joined_list "line break"
shipped_defaults
CUR=dns; opt enabled 1
sec route; opt server 1.1.1.1; opt via "direct${NL}USER = root"
run_fail newline_in_route "line break"

shipped_defaults
CUR=main; opt openproxy maybe
run_fail bad_boolean "boolean"

# routes
shipped_defaults
CUR=dns; opt enabled 1
for h in 1.1.1.1 2.2.2.2 3.3.3.3; do sec route; opt server $h; done
run_ok four_routes_ok "LOG = 2
PORT = 127.0.0.1:8443@443
SNITIMEOUT = 30
LDNS = 127.0.0.1:5354
DNS = 9.9.9.9
DNS = 1.1.1.1
DNS = 2.2.2.2
DNS = 3.3.3.3"
sec route; opt server 5.5.5.5
run_fail five_routes "more than 4"

# disabled routes do not count towards the limit
shipped_defaults
CUR=dns; opt enabled 1
for h in 1.1.1.1 2.2.2.2 3.3.3.3 4.4.4.4; do sec route; opt server $h; opt enabled 0; done
run_ok disabled_routes_skipped "LOG = 2
PORT = 127.0.0.1:8443@443
SNITIMEOUT = 30
LDNS = 127.0.0.1:5354
DNS = 9.9.9.9"

shipped_defaults
CUR=dns; opt enabled 1
sec route; opt enabled 1
run_fail route_without_server "no server"

# --- static checks and optional parse check --------------------------------
if sh -n "$INIT"; then echo "ok   sh -n"; else echo "FAIL sh -n"; FAILS=$((FAILS + 1)); fi
if command -v shellcheck >/dev/null 2>&1; then
	if shellcheck -s sh -e SC3043,SC2034 "$INIT"; then echo "ok   shellcheck"
	else echo "FAIL shellcheck"; FAILS=$((FAILS + 1)); fi
fi

if [ -n "$BIN" ] && [ -x "$BIN" ]; then
	# The binary has no parse-only mode; a config that binds nothing
	# useful is still rejected quickly, so just require "no parse error".
	shipped_defaults
	CUR=main; opt openproxy yes
	CUR=dns; opt enabled 1
	rm -rf "$WORK/run"; generate_conf "$ZR_RUN_DIR/zroxy.conf"
	out="$(timeout 2 "$BIN" -c "$ZR_RUN_DIR/zroxy.conf" 2>&1 </dev/null)"
	if printf '%s' "$out" | grep -qi 'unknown\|invalid\|unrecognized'; then
		echo "FAIL zroxy rejected generated file: $out"; FAILS=$((FAILS + 1))
	else
		echo "ok   zroxy accepts generated file"
	fi
fi

if [ "$FAILS" -ne 0 ]; then echo "$FAILS failure(s)"; exit 1; fi
echo "all passed"
