#! /bin/sh

# Usage
#
# Build wheels of all dependencies across glibc and musl
# ./build.sh deps
#
# Build nuitka binaries for glibc and musl
# ./build.sh nuitka
#
# Run test across all distros
# ./build.sh test
#
# Run command on specific container
# ./build.sh IMAGE command subcommand
#
# Commands
#   build - sub-commands: deps nuitka
#   test - sub-commands: alpine ubuntu debian opensuse, test.py flags

if [ -f "/.dockerenv" ]; then
    # Running inside container
    DISTRO=`cat /etc/os-release | grep ^ID | head -n 1 | cut -d"=" -f2 | sed 's/"//g'`
    SHELL="bash"

    export PROXY="$1"
    export PAC="$2"
    export USERNAME="$3"
    export AUTH=""

    # build or test - else $SHELL
    COMMAND=""
    if [ ! -z "$4" ]; then
        COMMAND="$4"
    fi

    # build sub-commands: nuitka or deps
    # test sub-commands passed as flags to test.py
    SUBCOMMAND=""
    if [ ! -z "$5" ]; then
        SUBCOMMAND="$5"
    fi

    if [ "$DISTRO" = "alpine" ]; then

        apk update && apk upgrade
        apk add curl psmisc python3
        python3 -m ensurepip
        if [ "$COMMAND" = "build" ]; then
            apk add ccache gcc musl-dev patchelf python3-dev upx
        else
            apk add dbus gnome-keyring
        fi

        SHELL="sh"

    elif [ "$DISTRO" = "centos" ]; then

        # Avoid random mirror
        cd /etc/yum.repos.d
        for file in `ls`; do sed -i~ 's/^mirrorlist/#mirrorlist/' $file; done
        for file in `ls`; do sed -i~~ 's/^#baseurl/baseurl/' $file; done
        cd

        yum update -y
        yum install -y psmisc python3
        python3 -m ensurepip
        if [ "$COMMAND" = "build" ]; then
            yum install -y ccache libffi-devel patchelf python3-devel upx
        else
            yum install -y gnome-keyring
        fi

    elif [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ] || [ "$DISTRO" = "linuxmint" ]; then

        apt update -y && apt upgrade -y
        apt install -y curl dbus gnome-keyring psmisc python3 python3-pip

        export AUTH="--auth=NONEGOTIATE"

    elif [ "$DISTRO" = "opensuse-tumbleweed" ] || [ "$DISTRO" = "opensuse-leap" ]; then

        zypper -n update
        zypper -n install curl dbus-1 gnome-keyring psmisc python3 python3-pip

        export AUTH="--auth=NONEGOTIATE"

    elif [ "$DISTRO" = "void" ]; then

        xbps-install -Suy xbps
        xbps-install -Sy curl dbus gnome-keyring psmisc python3
        python3 -m ensurepip

        SHELL="sh"

    else
        echo "Unknown distro $DISTRO"
        $SHELL
        exit
    fi

    MUSL=`ldd /bin/ls | grep musl`
    if [ -z "$MUSL" ]; then
        ABI="glibc"
    else
        ABI="musl"
    fi
    export PXBIN="/px/px.dist-linux-$ABI-x86_64/px.dist/px"
    export WHEELS="/px/px.dist-wheels-linux-$ABI-x86_64/px.dist-wheels"

    if [ "$COMMAND" != "build" ]; then
        dbus-run-session -- $SHELL -c 'echo "abc" | gnome-keyring-daemon --unlock'
    fi

    cd /px
    if [ "$COMMAND" = "build" ]; then
        if [ "$SUBCOMMAND" = "nuitka" ]; then
            # Install tools
            python3 -m pip install --upgrade pip setuptools build wheel
            python3 -m pip install --upgrade nuitka

            # Install wheel dependencies
            # nuitka depends on deps - run deps first
            python3 -m pip install px-proxy --no-index -f $WHEELS

            # Build Nuitka binary
            python3 tools.py --nuitka
        elif [ "$SUBCOMMAND" = "deps" ]; then
            rm -rf $WHEELS

            # Run for all Python versions
            for pyver in `ls /opt/python/cp* -d`
            do
                # Install tools
                $pyver/bin/python3 -m pip install --upgrade pip setuptools build wheel

                # Build dependency wheels
                $pyver/bin/python3 tools.py --deps
            done

            # Package all wheels
            /opt/python/cp310-cp310/bin/python3 tools.py --depspkg
        else
            $SHELL
        fi
    else
        python3 -m pip install --upgrade pip
        python3 -m pip install px-proxy --no-index -f $WHEELS

        if [ "$COMMAND" = "test" ]; then
            python3 test.py --binary --pip --proxy=$PROXY --pac=$PAC --username=$USERNAME $AUTH $SUBCOMMAND
        else
            $SHELL
        fi
    fi

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

    # Python wheel containers for musl and glibc
    MUSL="quay.io/pypa/musllinux_1_1_x86_64"
    GLIBC="quay.io/pypa/manylinux2014_x86_64"

    DOCKERCMD="docker run -it --rm --network host --privileged -v `pwd`:/px -v /root/.local/share:/root/.local/share"
    if [ "$1" = "deps" ] || [ "$1" = "nuitka" ]; then
        for image in $MUSL $GLIBC
        do
            $DOCKERCMD $image /px/build.sh "$PROXY" "$PAC" "$USERNAME" build $1
        done
    elif [ "$1" = "test" ]; then
        SUBCOMMAND="$3"
        if [ "$2" = "alpine" ]; then
            IMAGES="alpine alpine:3.11"
        elif [ "$2" = "ubuntu" ]; then
            IMAGES="ubuntu ubuntu:focal"
        elif [ "$2" = "debian" ]; then
            IMAGES="debian debian:oldstable"
        elif [ "$2" = "mint" ]; then
            IMAGES="linuxmintd/mint20.3-amd64"
        elif [ "$2" = "opensuse" ]; then
            IMAGES="opensuse/tumbleweed opensuse/leap:15.1"
        else
            SUBCOMMAND="$2"
            IMAGES="alpine ubuntu debian opensuse/tumbleweed"
        fi
        for image in $IMAGES
        do
            $DOCKERCMD $image /px/build.sh "$PROXY" "$PAC" "$USERNAME" test "$SUBCOMMAND"
        done
    else
        if [ "$1" = "musl" ]; then
            IMAGE="$MUSL"
        elif [ "$1" = "glibc" ]; then
            IMAGE="$GLIBC"
        else
            IMAGE="$1"
        fi

        $DOCKERCMD $IMAGE /px/build.sh "$PROXY" "$PAC" "$USERNAME" $2 $3
    fi
fi