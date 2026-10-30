#!/bin/sh
set -eu

REALM=CORP.TEST
DOMAIN=CORP
ADMIN_PASSWORD='ScenarioAdmin1!'

rm -f /etc/samba/smb.conf
samba-tool domain provision \
    --realm="$REALM" --domain="$DOMAIN" --server-role=dc \
    --dns-backend=SAMBA_INTERNAL --adminpass="$ADMIN_PASSWORD" \
    --option='interfaces=lo eth0' --option='bind interfaces only=yes' \
    --option='vfs objects=acl_xattr' \
    --option='acl_xattr:ignore system acls=yes'
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

samba-tool user create pxgood 'GoodPass1!'
samba-tool user create pxother 'OtherPass2!'
samba-tool user create squid-sso 'ServicePass3!'
samba-tool spn add HTTP/squid-sso.corp.test squid-sso
samba-tool spn add HTTP/localhost squid-sso
samba-tool spn add HTTP/toxiproxy squid-sso
samba-tool domain exportkeytab /shared/squid-http.keytab \
    --principal=HTTP/squid-sso.corp.test
samba-tool domain exportkeytab /shared/squid-http.keytab \
    --principal=HTTP/localhost
samba-tool domain exportkeytab /shared/squid-http.keytab \
    --principal=HTTP/toxiproxy
chmod 0644 /shared/squid-http.keytab

samba -i --debug-stdout &
SAMBA_PID=$!
trap 'kill "$SAMBA_PID"' EXIT INT TERM

# The AD DC already owns the machine account and winbind privileged pipe.
# Keeping Squid here avoids a fragile second member join solely for ntlm_auth.
for _ in $(seq 1 60); do
    [ -S /var/lib/samba/winbindd_privileged/pipe ] && break
    sleep 1
done
[ -S /var/lib/samba/winbindd_privileged/pipe ]
usermod -a -G winbindd_priv proxy

mkdir -p /var/spool/squid /var/log/squid
chown proxy:proxy /shared/squid-http.keytab
cat >/etc/squid/squid.conf <<'EOF'
visible_hostname squid-sso.corp.test
http_port 3128
acl SSL_ports port 443 8443 8888 18443
acl Safe_ports port 80 443 8080 8443 8888 18080 18443
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
# Squid's default 512 KB request buffer makes it abort uploads whose bodies arrive while the
# auth helpers are still busy (plain curl loses about 10% of 60 concurrent 3 MB uploads), a Squid
# limit no client can work around. A larger buffer keeps the lab deterministic. There is no
# maxconn limit here: after a run of aborted uploads Squid kept counting the closed connections
# and answered 403 to every later request from the same address.
client_request_buffer_max_size 16 MB
auth_param negotiate program /usr/lib/squid/negotiate_kerberos_auth -k /shared/squid-http.keytab -s HTTP/squid-sso.corp.test
auth_param negotiate children 20 startup=2 idle=2
auth_param ntlm program /usr/bin/ntlm_auth --helper-protocol=squid-2.5-ntlmssp --domain=CORP
auth_param ntlm children 20 startup=2 idle=2
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all
access_log stdio:/var/log/squid/access.log
cache_log stdio:/var/log/squid/cache.log
cache deny all
coredump_dir /var/spool/squid
EOF

# A second Squid on 3129 closes every client and origin connection after its
# response, as many corporate proxies do. It shares the helpers' winbind pipe
# and keytab so NTLM and Kerberos run against both connection policies.
sed -e 's/^http_port 3128/http_port 3129/' \
    -e 's#/var/log/squid/access.log#/var/log/squid/access-close.log#' \
    -e 's#/var/log/squid/cache.log#/var/log/squid/cache-close.log#' \
    /etc/squid/squid.conf >/etc/squid/squid-close.conf
cat >>/etc/squid/squid-close.conf <<'CONF'
pid_filename /run/squid-close.pid
client_persistent_connections off
server_persistent_connections off
CONF

# A third Squid on 3130 models an AD-joined corporate proxy that advertises only
# "Proxy-Authenticate: Negotiate" (no bare "NTLM" scheme), using Squid's own
# negotiate_wrapper_auth to multiplex the same Kerberos and NTLM helpers behind
# it. negotiate_wrapper_auth picks a helper by checking whether the *decoded*
# token's first 8 bytes are the literal ASCII "NTLMSSP\0" signature
# (src/auth/negotiate/wrapper/negotiate_wrapper.cc upstream); a standards-compliant
# SPNEGO client (MIT krb5's GSSAPI, which curl/mcurl use on Linux, with gss-ntlmssp
# as the NTLM mechanism) always wraps that signature inside an RFC 4178
# negTokenInit ASN.1 envelope, so the check never matches and every Negotiate
# token - Kerberos or SPNEGO-wrapped NTLM alike - is handed to the Kerberos
# helper. A pure-Kerberos Negotiate client still authenticates normally through
# this port; a client that falls back to NTLM inside SPNEGO gets stuck at the
# first 407 instead (docs/testing.md has the full trace). This is a Squid
# limitation, not a px/mcurl one - it is kept as the lab's only "Negotiate-only"
# port because real Windows SSPI is reported to send its NTLM fallback as a bare,
# unwrapped NTLMSSP token under the Negotiate header, which this helper does
# detect; the Windows CI job is what actually settles that for SSPI.
sed -e 's/^http_port 3128/http_port 3130/' \
    -e 's#/var/log/squid/access.log#/var/log/squid/access-wrapper.log#' \
    -e 's#/var/log/squid/cache.log#/var/log/squid/cache-wrapper.log#' \
    -e "s#^auth_param negotiate program .*#auth_param negotiate program /usr/lib/squid/negotiate_wrapper_auth --ntlm /usr/bin/ntlm_auth --helper-protocol=squid-2.5-ntlmssp --domain=CORP --kerberos /usr/lib/squid/negotiate_kerberos_auth -k /shared/squid-http.keytab -s HTTP/squid-sso.corp.test#" \
    -e '/^auth_param ntlm /d' \
    /etc/squid/squid.conf >/etc/squid/squid-wrapper.conf
cat >>/etc/squid/squid-wrapper.conf <<'CONF'
pid_filename /run/squid-wrapper.pid
CONF

touch /shared/dc-ready
squid -n squidclose -f /etc/squid/squid-close.conf -NYCd 1 &
squid -n squidwrapper -f /etc/squid/squid-wrapper.conf -NYCd 1 &
exec squid -NYCd 1
