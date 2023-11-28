#! /bin/sh

# Usage
#
# ./build.sh [-b] [-t] [-i IMAGE] [-s SUBCOMMAND]
#
# Build -b
#   IMAGE = glibc | musl | all (default) | any Docker tag
#   SUBCOMMAND = -d = deps | -n = nuitka | all (default)
# Test -t
#   IMAGE = alpines | ubuntus | debians | mints | opensuses | any Docker tag
#   SUBCOMMAND forwarded to test.py
#
# Build wheels of all dependencies across glibc and musl
# ./build.sh -b -d
#
# Build nuitka binaries for glibc and musl
# ./build.sh -b -n
#
# Build both wheels and nuita binaries for glibc and musl
# ./build.sh -b
#
# Run test across all distros
# ./build.sh -t
#
# Run SHELL on specific container
# ./build.sh -i IMAGE

OS=`uname -s`

# Parse command line
while getopts 'i:btdns:' OPTION; do
    case "$OPTION" in
        i)
            IMAGE="$OPTARG"
            ;;
        b)
            BUILD="yes"
            ;;
        t)
            TEST="yes"
            ;;
        d)
            DEPS="yes"
            ;;
        n)
            NUITKA="yes"
            ;;
        s)
            SUBCOMMAND="$OPTARG"
            ;;
    esac
done
shift "$(($OPTIND -1))"

# Check if env vars are set
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

if [ -f "/.dockerenv" ]; then
    # Running inside container
    DISTRO=`cat /etc/os-release | grep ^ID | head -n 1 | cut -d"=" -f2 | sed 's/"//g'`
    SHELL="bash"

    export AUTH=""

    if [ "$DISTRO" = "alpine" ]; then

        apk update && apk upgrade
        apk add curl psmisc python3
        python3 -m ensurepip
        if [ "$BUILD" = "yes" ]; then
            apk add ccache gcc musl-dev patchelf python3-dev upx
        else
            apk add dbus gnome-keyring
        fi

        SHELL="sh"

    elif [ "$DISTRO" = "centos" ] || [ "$DISTRO" = "rocky" ]; then

        # Avoid random mirror
        cd /etc/yum.repos.d
        for file in `ls`; do sed -i~ 's/^mirrorlist/#mirrorlist/' $file; done
        for file in `ls`; do sed -i~~ 's/^#baseurl/baseurl/' $file; done
        cd

        yum update -y
        yum install -y psmisc python3
        python3 -m ensurepip
        if [ "$BUILD" = "yes" ]; then
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

    if [ -z "$BUILD" ]; then
        # For test and SHELL only
        dbus-run-session -- $SHELL -c 'echo "abc" | gnome-keyring-daemon --unlock'
    fi

    cd /px
    if [ "$BUILD" = "yes" ]; then
        if [ "$DEPS" = "yes" ] || [ ! -d "$WHEELS" ]; then
            # Also run if $WHEELS does not exist since NUITKA depends on wheels
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
            /opt/python/cp312-cp312/bin/python3 tools.py --depspkg
        fi

        if [ "$NUITKA" = "yes" ]; then
            # Install tools
            python3 -m pip install --upgrade pip setuptools build wheel
            python3 -m pip install --upgrade nuitka

            # Install wheel dependencies
            python3 -m pip install px-proxy --no-index -f $WHEELS

            # Build Nuitka binary
            python3 tools.py --nuitka
        fi
    else
        python3 -m pip install --upgrade pip

        if [ "$TEST" = "yes" ]; then
            if [ ! -d "$WHEELS" ]; then
                echo "Wheels missing => ./build.sh -b -d"
                $SHELL
                exit
            fi

            # Install wheel dependencies
            python3 -m pip install px-proxy --no-index -f $WHEELS

            # Run tests
            python3 test.py --binary --pip --proxy=$PROXY --pac=$PAC --username=$USERNAME $AUTH $SUBCOMMAND
        else
            if [ -d "$WHEELS" ]; then
                # Install Px dependencies if available
                python3 -m pip install px-proxy --no-index -f $WHEELS
            fi

            # Start shell
            $SHELL
        fi
    fi

elif [ "$OS" = "Darwin" ]; then

    # Install brew
    if ! brew -v > /dev/null; then
        bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew update

    # Delete depspkg directory
    rm -rf px.dist-wheels-osx-x86_64

    for pyver in 3.7 3.8 3.9 3.10 3.11 3.12
    do
        # Install Python
        brew install python@$pyver

        PY="/usr/local/opt/python@$pyver/bin/python$pyver"

        # Tools
        $PY -m pip install --upgrade pip setuptools build wheel

        # Create wheel dependencies for this Python version
        $PY tools.py --deps
    done

    # Install build tools
    $PY -m pip install --upgrade nuitka twine
    brew install upx

    # Install wheel dependencies
    $PY -m pip install --upgrade px-proxy --no-index -f px.dist-wheels-osx-x86_64/px.dist-wheels

    # Create package of all dependencies
    $PY tools.py --depspkg

    # Build Nuitka
    $PY tools.py --nuitka

    # Uninstall Px
    $PY -m pip uninstall px-proxy -y

else
    # Start container

    # Python wheel containers for musl and glibc
    MUSL="quay.io/pypa/musllinux_1_1_x86_64"
    GLIBC="quay.io/pypa/manylinux2014_x86_64"

    DOCKERCMD="docker run -it --rm --network host --privileged -v `pwd`:/px -v /root/.local/share:/root/.local/share \
                -e PROXY=\"$PROXY\" -e PAC=\"$PAC\" -e USERNAME=\"$USERNAME\""

    if [ "$BUILD" = "yes" ]; then
        # Which image to load
        if [ -z "$IMAGE" ] || [ "$IMAGE" = "all" ]; then
            IMAGE="$MUSL $GLIBC"
        elif [ "$IMAGE" = "musl" ]; then
            IMAGE="$MUSL"
        elif [ "$IMAGE" = "glibc" ]; then
            IMAGE="$GLIBC"
        fi

        # What to build
        if [ "$DEPS" = "yes" ] && [ -z "$NUITKA" ]; then
            SUBCOMMAND="-d"
        elif [ "$NUITKA" = "yes" ] && [ -z "$DEPS" ]; then
            SUBCOMMAND="-n"
        else
            SUBCOMMAND="-d -n"
        fi

        # Build on each image
        for image in $IMAGE
        do
            $DOCKERCMD $image /px/build.sh -b $SUBCOMMAND
        done
    elif [ "$TEST" = "yes" ]; then
        # Which image to test
        if [ -z "$IMAGE" ]; then
            IMAGE="alpine ubuntu debian opensuse/tumbleweed"
        elif [ "$SUBCOMMAND" = "alpines" ]; then
            IMAGE="alpine alpine:3.11"
        elif [ "$SUBCOMMAND" = "ubuntus" ]; then
            IMAGE="ubuntu ubuntu:focal"
        elif [ "$SUBCOMMAND" = "debians" ]; then
            IMAGE="debian debian:oldstable"
        elif [ "$SUBCOMMAND" = "mints" ]; then
            IMAGE="linuxmintd/mint21.2-amd64"
        elif [ "$SUBCOMMAND" = "opensuses" ]; then
            IMAGE="opensuse/tumbleweed opensuse/leap:15.1"
        fi

        # Test on each image
        for image in $IMAGE
        do
            # Forward any commands to test.py
            if [ ! -z "$SUBCOMMAND" ]; then
                SUBCOMMAND="-s \"$SUBCOMMAND\""
            fi
            $DOCKERCMD $image /px/build.sh -t "$SUBCOMMAND"
        done
    else
        if [ -z "$IMAGE" ]; then
            echo "No image specified"
            exit 1
        elif [ "$IMAGE" = "musl" ]; then
            IMAGE="$MUSL"
        elif [ "$IMAGE" = "glibc" ]; then
            IMAGE="$GLIBC"
        fi

        $DOCKERCMD $IMAGE /px/build.sh
    fi
fi