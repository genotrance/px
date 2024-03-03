#! /bin/sh

# Start dbus and gnome-keyring
export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --fork --config-file=/usr/share/dbus-1/session.conf --print-address`
echo "abc" | gnome-keyring-daemon --unlock

# Forward all CLI arguments to px
px "$@"