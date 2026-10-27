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
samba-tool domain exportkeytab /shared/squid-http.keytab \
    --principal=HTTP/squid-sso.corp.test
samba-tool domain exportkeytab /shared/squid-http.keytab \
    --principal=HTTP/localhost
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
acl max_client_connections maxconn 64
http_access deny max_client_connections
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
touch /shared/dc-ready
exec squid -NYCd 1
