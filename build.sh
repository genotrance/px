#! /bin/sh

if [ -f "/.dockerenv" ]; then
    # Running inside container
    DISTRO=`cat /etc/os-release | grep ^ID | head -n 1 | cut -d"=" -f2 | sed 's/"//g'`
    SHELL="bash"

    export PROXY="$1"
    export PAC="$2"
    export USERNAME="$3"

    # build or test
    COMMAND="test"
    if [ ! -z "$4" ]; then
        COMMAND="$4"
    fi

    if [ "$DISTRO" = "alpine" ]; then

        apk update && apk upgrade
        apk add curl dbus gcc gnome-keyring linux-headers musl-dev psmisc python3 python3-dev
        python3 -m ensurepip
        if [ "$COMMAND" = "build" ]; then
            apk add ccache libffi-dev patchelf py3-dbus upx
        fi

        SHELL="sh"

    elif [ "$DISTRO" = "centos" ]; then

        yum update -y
        yum install -y gnome-keyring psmisc
        if [ "$COMMAND" = "build" ]; then
            yum install -y ccache dbus-devel libffi-devel patchelf python36-cryptography upx
        fi

    elif [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ] || [ "$DISTRO" = "linuxmint" ]; then

        apt update -y && apt upgrade -y
        apt install -y curl dbus gnome-keyring psmisc python3 python3-dev python3-pip
        if [ "$COMMAND" = "build" ]; then
            apt install -y ccache patchelf python3-dbus python3-secretstorage upx zlib1g zlib1g-dev
        fi

    elif [ "$DISTRO" = "opensuse-tumbleweed" ] || [ "$DISTRO" = "opensuse-leap" ]; then

        zypper -n update
        zypper -n install curl dbus-1 gnome-keyring psmisc python3 python3-pip
        if [ "$DISTRO" = "opensuse-leap" ]; then
            zypper -n install gcc
        fi

    elif [ "$DISTRO" = "void" ]; then

        xbps-install -Suy xbps
        xbps-install -Sy curl dbus gcc gnome-keyring psmisc python3 python3-devel
        python3 -m ensurepip

        SHELL="sh"

    else
        echo "Unknown distro $DISTRO"
        $SHELL
        exit
    fi

    MUSL=`ldd /bin/ls | grep musl`
    if [ -z "$MUSL" ]; then
        PXBIN="/px/px.dist-linux-glibc-x86_64/px.dist/px"
    else
        PXBIN="/px/px.dist-linux-musl-x86_64/px.dist/px"
    fi

    dbus-run-session -- $SHELL -c 'echo "abc" | gnome-keyring-daemon --unlock'

    cd /px
    if [ "$COMMAND" = "build" ]; then
        python3 -m pip install --upgrade pip setuptools jeepney==0.7.1

        python3 tools.py --setup

        python3 px.py --username=$USERNAME --password
    else
        python3 -m pip install --upgrade pip setuptools netifaces psutil

        $PXBIN --username=$USERNAME --password
    fi

    $SHELL
else
    # Start container
    if [ -z "$PROXY" ]; then
        echo "PROXY not configured"
        exit
    fi

    if [ -z "$PAC" ]; then
        echo "PAC not configured"
        exit
    fi

    if [ -z "$USERNAME" ]; then
        echo "USERNAME not configured"
        exit
    fi

    docker run -it --rm --network host --privileged -v `pwd`:/px $1 /px/build.sh "$PROXY" "$PAC" "$USERNAME" $2
fi