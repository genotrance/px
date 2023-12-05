#! /bin/sh

USAGE="
./build.sh [-i IMAGE] ([-b] [-d] [-n] [-a ARCH] [-v PYVERSION]) ([-t] [-s SUBCOMMAND])

-b = build
  -i IMAGE = glibc | musl | any Docker tag - default = glibc + musl
  -d = deps
  -n = nuitka
  -a ARCH = aarch64 | i686 ... - default = host architecture
  -v PYVERSION = 3.12 | 3.11 ... - default n-1 + all
-t = test
  -i IMAGE = alpines | ubuntus | debians | mints | opensuses | any Docker tag
  -s SUBCOMMAND = forwarded to test.py

Build wheels of all dependencies across glibc and musl
./build.sh -b -d

Build nuitka binaries for glibc and musl
./build.sh -b -n

Build both wheels and nuita binaries for glibc and musl for Python 3.11
./build.sh -b -v 3.11

Run test across all distros
./build.sh -t

Run SHELL on specific container
./build.sh -i IMAGE
"

OS=`uname -s`

# Parse command line
while getopts 'i:bdna:v:ts:' OPTION; do
    case "$OPTION" in
        i)
            IMAGE="$OPTARG"
            ;;
        b)
            BUILD="yes"
            ;;
        d)
            DEPS="yes"
            ;;
        n)
            NUITKA="yes"
            ;;
        a)
            ARCH="$OPTARG"
            ;;
        v)
            PYVERSION="$OPTARG"
            ;;
        t)
            TEST="yes"
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
    MUSL=`ldd /bin/ls | grep musl`
    if [ -z "$MUSL" ]; then
        ABI="glibc"
    else
        ABI="musl"
    fi
    ARCH=`uname -m`

    export PXBIN="/px/px.dist-linux-$ABI-$ARCH/px.dist/px"
    export WHEELS="/px/px.dist-wheels-linux-$ABI-$ARCH/px.dist-wheels"
    export AUTH=""

    # Pick latest-1 python if manylinux / musllinux
    export PY="/opt/python/`ls -v /opt/python | tail -n 2 | head -n 1`/bin/python3"

    # Adjust Python version if specified with -v
    if [ ! -z "$PYVERSION" ]; then
        for pyver in `ls /opt/python/cp* -d`
        do
            CVER=`$pyver/bin/python3 -V | cut -d ' ' -f 2 | cut -d '.' -f 1-2`
            if [ "$CVER" = "$PYVERSION" ]; then
                export PY="$pyver/bin/python3"
                break
            fi
        done
    fi

    # Python not found - default - will be installed if needed
    if [ ! -f "$PY" ]; then
        export PY="python3"
        echo "Using `python3 -V` - not manylinux / musllinux"
    fi

    if [ "$DISTRO" = "alpine" ]; then

        apk update && apk upgrade
        apk add curl psmisc
        if [ "$PY" = "python3" ]; then
            # Not manylinux / musllinux
            apk add python3
            $PY -m ensurepip
            if [ "$BUILD" = "yes" ]; then
                apk add python3-dev
            fi
        fi
        if [ "$BUILD" = "yes" ]; then
            apk add ccache gcc musl-dev patchelf upx
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
        yum install -y psmisc
        if [ "$PY" = "python3" ]; then
            # Not manylinux / musllinux
            yum install -y python3
            $PY -m ensurepip
            if [ "$BUILD" = "yes" ]; then
                yum install -y python3-devel
            fi
        fi
        if [ "$BUILD" = "yes" ]; then
            yum install -y ccache libffi-devel patchelf upx
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
        $PY -m ensurepip

        SHELL="sh"

    else
        echo "Unknown distro $DISTRO"
        $SHELL
        exit
    fi

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
                if [ ! -z "$PYVERSION" ]; then
                    # Run only for Python version specified with -v
                    CVER=`$pyver/bin/python3 -V | cut -d ' ' -f 2 | cut -d '.' -f 1-2`
                    if [ "$CVER" != "$PYVERSION" ]; then
                        continue
                    fi
                fi

                # Install tools
                $pyver/bin/python3 -m pip install --upgrade pip setuptools build wheel

                # Build dependency wheels
                $pyver/bin/python3 tools.py --deps
            done

            # If no wheels generated, exit
            if [ ! -d "$WHEELS" ]; then
                echo "No wheels generated - $PYVERSION not found"
                $SHELL
                exit
            fi

            # Package all wheels
            $PY tools.py --depspkg
        fi

        if [ "$NUITKA" = "yes" ]; then
            # Install tools
            $PY -m pip install --upgrade pip setuptools build wheel
            $PY -m pip install --upgrade nuitka

            # Install wheel dependencies
            $PY -m pip install px-proxy --no-index -f $WHEELS

            # Build Nuitka binary
            $PY tools.py --nuitka
        fi
    else
        $PY -m pip install --upgrade pip

        if [ "$TEST" = "yes" ]; then
            if [ ! -d "$WHEELS" ]; then
                echo "Wheels missing => ./build.sh -b -d"
                $SHELL
                exit
            fi

            # Install wheel dependencies
            $PY -m pip install px-proxy --no-index -f $WHEELS

            # Run tests
            $PY test.py --binary --pip --proxy=$PROXY --pac=$PAC --username=$USERNAME $AUTH $SUBCOMMAND
        else
            if [ -d "$WHEELS" ]; then
                # Install Px dependencies if available
                $PY -m pip install px-proxy --no-index -f $WHEELS
            fi

            # Start shell
            $SHELL
        fi
    fi

elif [ "$OS" = "Darwin" ]; then
    # OSX build

    # Install brew
    if ! brew -v > /dev/null; then
        bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew update

    # Delete depspkg directory
    rm -rf px.dist-wheels-osx-x86_64

    for pyver in 3.7 3.8 3.9 3.10 3.11 3.12
    do
        # Run only for Python version if specified with -v
        if [ ! -z "$PYVERSION" ] && [ "$pyver" != "$PYVERSION" ]; then
            continue
        fi

        # Install Python
        brew install python@$pyver

        export PY="/usr/local/opt/python@$pyver/bin/python$pyver"

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
    # Start containers

    # Detect architecture
    if [ -z "$ARCH" ]; then
        ARCH=`uname -m`
    elif [ "$ARCH" != `uname -m` ]; then
        # Install binfmt to add support for multiple architectures
        docker run --privileged --rm tonistiigi/binfmt --install all
    fi

    # Python wheel containers for musl and glibc
    MUSL="quay.io/pypa/musllinux_1_1_$ARCH"
    GLIBC="quay.io/pypa/manylinux2014_$ARCH"

    DOCKERCMD="docker run -it --rm --network host --privileged -v `pwd`:/px -v /root/.local/share:/root/.local/share \
                -e PROXY=$PROXY -e PAC=$PAC -e USERNAME=$USERNAME"

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

        # Forward Python version to build
        if [ ! -z "$PYVERSION" ]; then
            SUBCOMMAND="$SUBCOMMAND -v $PYVERSION"
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

        # Forward any commands to test.py
        if [ ! -z "$SUBCOMMAND" ]; then
            SUBCOMMAND="-s \"$SUBCOMMAND\""
        fi

        # Test on each image
        for image in $IMAGE
        do
            $DOCKERCMD $image /px/build.sh -t "$SUBCOMMAND"
        done
    else
        if [ -z "$IMAGE" ]; then
            echo "$USAGE"
            exit 1
        elif [ "$IMAGE" = "musl" ]; then
            IMAGE="$MUSL"
        elif [ "$IMAGE" = "glibc" ]; then
            IMAGE="$GLIBC"
        fi

        $DOCKERCMD $IMAGE /px/build.sh
    fi

fi