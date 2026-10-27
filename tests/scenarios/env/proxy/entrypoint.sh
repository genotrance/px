#!/bin/sh
set -eu

SCHEME=${SCHEME:-basic}
mkdir -p /run/samba /var/log/samba /var/spool/squid /etc/squid

cat >/etc/krb5.conf <<'EOF'
[libdefaults]
 default_realm = CORP.TEST
 dns_lookup_realm = false
 dns_lookup_kdc = false
 rdns = false
[realms]
 CORP.TEST = {
  kdc = dc.corp.test
  admin_server = dc.corp.test
 }
[domain_realm]
 .corp.test = CORP.TEST
 corp.test = CORP.TEST
EOF

cat >/etc/squid/common.conf <<'EOF'
visible_hostname SCENARIO_HOSTNAME
http_port 3128
acl SSL_ports port 443 8443 18443
acl Safe_ports port 80 443 8080 8443 18080 18443 18081 18888
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
acl max_client_connections maxconn 16
http_access deny max_client_connections
access_log stdio:/var/log/squid/access.log
cache_log /var/log/squid/cache.log
cache deny all
coredump_dir /var/spool/squid
EOF
sed -i "s/SCENARIO_HOSTNAME/$(hostname -f)/" /etc/squid/common.conf

case "$SCHEME" in
basic|close|child)
    printf 'pxgood:%s\npxother:%s\n' \
        "$(openssl passwd -apr1 'GoodPass1!')" \
        "$(openssl passwd -apr1 'OtherPass2!')" >/etc/squid/basic.passwd
    cat >/etc/squid/auth.conf <<'EOF'
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/basic.passwd
auth_param basic realm Px corporate proxy
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all
EOF
    ;;
digest)
    python3 - <<'PY' >/etc/squid/digest.passwd
import hashlib
for user, password in (("pxgood", "GoodPass1!"), ("pxother", "OtherPass2!")):
    value = hashlib.md5(f"{user}:Px corporate proxy:{password}".encode()).hexdigest()
    print(f"{user}:Px corporate proxy:{value}")
PY
    cat >/etc/squid/auth.conf <<'EOF'
auth_param digest program /usr/lib/squid/digest_file_auth -c /etc/squid/digest.passwd
auth_param digest realm Px corporate proxy
auth_param digest nonce_garbage_interval 5 minutes
auth_param digest nonce_max_duration 30 minutes
auth_param digest nonce_max_count 50
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all
EOF
    ;;
sso)
    while [ ! -f /shared/dc-ready ]; do sleep 1; done
    cat >/etc/samba/smb.conf <<'EOF'
[global]
 workgroup = CORP
 realm = CORP.TEST
 security = ADS
 password server = dc.corp.test
 kerberos method = secrets and keytab
 winbind use default domain = yes
 idmap config * : backend = tdb
 idmap config * : range = 3000-7999
EOF
    printf '%s\n' 'ScenarioAdmin1!' | net ads join -S dc.corp.test -U Administrator
    printf 'nameserver 127.0.0.11\noptions ndots:0\n' >/etc/resolv.conf
    winbindd
    cp /shared/squid-http.keytab /etc/squid/squid-http.keytab
    chown proxy:proxy /etc/squid/squid-http.keytab
    cat >/etc/squid/auth.conf <<'EOF'
auth_param negotiate program /usr/lib/squid/negotiate_kerberos_auth -k /etc/squid/squid-http.keytab -s HTTP/squid-sso.corp.test
auth_param negotiate children 20 startup=2 idle=2
auth_param ntlm program /usr/bin/ntlm_auth --helper-protocol=squid-2.5-ntlmssp --domain=CORP
auth_param ntlm children 20 startup=2 idle=2
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all
EOF
    ;;
parent)
    cat >/etc/squid/auth.conf <<'EOF'
http_access allow all
EOF
    ;;
*)
    echo "Unknown SCHEME=$SCHEME" >&2
    exit 2
    ;;
esac

if [ "$SCHEME" = close ]; then
    cat >>/etc/squid/common.conf <<'EOF'
client_persistent_connections off
server_persistent_connections off
EOF
fi
if [ "$SCHEME" = child ]; then
    cat >>/etc/squid/common.conf <<'EOF'
cache_peer squid-parent.corp.test parent 3128 0 no-query default
never_direct allow all
EOF
fi

cat /etc/squid/common.conf /etc/squid/auth.conf >/etc/squid/squid.conf
exec squid -NYCd 1
