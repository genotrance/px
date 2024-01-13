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

Run build.sh on specific container
./build.sh -i IMAGE

Run command on specific container
./build.sh -i IMAGE -s command
"

OS=`uname -s`

# Parse command line
while getopts 'Di:bdna:v:ts:' OPTION; do
    case "$OPTION" in
        D)
            DOCKERBUILD="yes"
            ;;
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

# Venv related
VPATH="import sys; print('py' + sys.version.split()[0])"

setup_venv() {
    VENV=$HOME/pyvenv/`$1 -c "$VPATH"`
    echo "Setup $VENV"
    $1 -m venv $VENV
    . $VENV/bin/activate
}

activate_venv() {
    VENV=$HOME/pyvenv/`$1 -c "$VPATH"`
    echo "Activate $VENV"
    . $VENV/bin/activate
}

gen_px_image() {
    # Python wheel containers for musl and glibc
    MUSL="quay.io/pypa/musllinux_1_1_$ARCH"
    GLIBC="quay.io/pypa/manylinux2014_$ARCH"

    # Check if image generated
    PX_IMAGE="px_$1"
    exists=`docker images | grep $PX_IMAGE`
    if [ -z "$exists" ]; then
        if [ "$1" = "musl" ]; then
            image="$MUSL"
        elif [ "$1" = "glibc" ]; then
            image="$GLIBC"
        else
            image="$1"
        fi

        echo "Generating $PX_IMAGE from $image"
        $DOCKERCMD $image /px/build.sh -D
        CONTAINER_ID=`docker ps -lq`
        docker commit $CONTAINER_ID $PX_IMAGE:latest
        docker rm $CONTAINER_ID
        echo "Generated $PX_IMAGE"
    fi
}

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

    export PROXY="127.0.0.1:3127"
    export USERNAME="test"
    export PX_PASSWORD="12345"
    export PX_CLIENT_USERNAME=$USERNAME
    export PX_CLIENT_PASSWORD=$PX_PASSWORD

    # Pick latest-1 python if manylinux / musllinux
    #   Nuitka support lags behind Python releases
    export PY="/opt/python/`ls -v /opt/python | grep cp | tail -n 2 | head -n 1`/bin/python3"

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
        echo "Using distro Python - not manylinux / musllinux"
    fi

    if [ "$DISTRO" = "alpine" ]; then

        if [ "$DOCKERBUILD" = "yes" ]; then
            apk update && apk upgrade
            apk add curl psmisc \
                python3 python3-dev \
                dbus gnome-keyring openssh \
                ccache gcc musl-dev patchelf upx
            if [ -f "/opt/_internal/static-libs-for-embedding-only.tar.xz" ]; then
                # Extract static libs for embedding if musllinux
                cd /opt/_internal && tar xf static-libs-for-embedding-only.tar.xz && cd -
            fi
        fi

        SHELL="sh"

    elif [ "$DISTRO" = "centos" ] || [ "$DISTRO" = "rocky" ]; then

        if [ "$DOCKERBUILD" = "yes" ]; then
            # Avoid random mirror
            cd /etc/yum.repos.d
            for file in `ls`; do sed -i~ 's/^mirrorlist/#mirrorlist/' $file; done
            for file in `ls`; do sed -i~~ 's/^#baseurl/baseurl/' $file; done
            cd

            yum update -y
            yum install -y psmisc \
                python3 python3-devel \
                gnome-keyring openssh \
                ccache libffi-devel patchelf upx
            yum clean all
            if [ -f "/opt/_internal/static-libs-for-embedding-only.tar.xz" ]; then
                # Extract static libs for embedding if manylinux
                cd /opt/_internal && tar xf static-libs-for-embedding-only.tar.xz && cd -
            fi
        fi

    elif [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ] || [ "$DISTRO" = "linuxmint" ]; then

        if [ "$DOCKERBUILD" = "yes" ]; then
            apt update -y && apt upgrade -y
            apt install -y curl psmisc python3 python3-venv \
                dbus gnome-keyring openssh-client \
                --no-install-recommends
            apt clean
        fi

        export AUTH="NONEGOTIATE"

    elif [ "$DISTRO" = "opensuse-tumbleweed" ] || [ "$DISTRO" = "opensuse-leap" ]; then

        if [ "$DOCKERBUILD" = "yes" ]; then
            zypper -n update
            zypper -n install curl psmisc python3 \
                dbus-1-python3 gnome-keyring openssh
            zypper cc -a
        fi

        export AUTH="NONEGOTIATE"

    elif [ "$DISTRO" = "void" ]; then

        if [ "$DOCKERBUILD" = "yes" ]; then
            xbps-install -Suy xbps
            xbps-install -Sy curl psmisc python3 \
                dbus gnome-keyring openssh
        fi

        SHELL="sh"

    elif [ "$DISTRO" = "arch" ] || [ "$DISTRO" = "manjaro" ]; then

        if [ "$DOCKERBUILD" = "yes" ]; then
            pacman -Syu --noconfirm
            pacman -S --noconfirm python3 \
                dbus gnome-keyring openssh
        fi

    else
        echo "Unknown distro $DISTRO"
        $SHELL
        exit
    fi

    if [ "$DOCKERBUILD" = "yes" ]; then
        # Run for all Python versions if manylinux/musllinux
        for pyver in `ls /opt/python/cp* -d -v`
        do
            if [ ! -z "$PYVERSION" ]; then
                # Run only for Python version specified with -v
                CVER=`$pyver/bin/python3 -V | cut -d ' ' -f 2 | cut -d '.' -f 1-2`
                if [ "$CVER" != "$PYVERSION" ]; then
                    continue
                fi
            fi

            # Setup venv for this Python version
            setup_venv $pyver/bin/python3

            # Install tools
            python3 -m pip install --upgrade pip setuptools build wheel
        done

        setup_venv $PY

        python3 -m pip install --upgrade pip setuptools build wheel auditwheel nuitka
        python3 -m pip cache purge
    else
        activate_venv $PY

        # Start dbus and gnome-keyring
        export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --fork --config-file=/usr/share/dbus-1/session.conf --print-address`
        echo "abc" | gnome-keyring-daemon --unlock

        cd /px
        if [ "$BUILD" = "yes" ]; then
            if [ "$DEPS" = "yes" ] || [ ! -d "$WHEELS" ]; then
                # Also run if $WHEELS does not exist since NUITKA depends on wheels
                rm -rf $WHEELS

                # Run for all Python versions if manylinux/musllinux
                for pyver in `ls /opt/python/cp* -d -v`
                do
                    if [ ! -z "$PYVERSION" ]; then
                        # Run only for Python version specified with -v
                        CVER=`$pyver/bin/python3 -V | cut -d ' ' -f 2 | cut -d '.' -f 1-2`
                        if [ "$CVER" != "$PYVERSION" ]; then
                            continue
                        fi
                    fi

                    # Setup venv for this Python version
                    activate_venv $pyver/bin/python3

                    # Build dependency wheels
                    python3 tools.py --deps
                done

                # Activate latest-1 Python version
                activate_venv $PY

                # If no wheels generated, exit
                if [ ! -d "$WHEELS" ]; then
                    echo "No wheels generated - $PYVERSION not found?"
                    $SHELL
                    exit
                fi

                # Create any wheel if not already
                python3 tools.py --wheel

                # Package all wheels
                python3 tools.py --depspkg
            fi

            if [ "$NUITKA" = "yes" ]; then
                # Install wheel dependencies
                python3 -m pip install px-proxy --no-index -f $WHEELS

                # Build Nuitka binary
                python3 tools.py --nuitka

                # Uninstall Px
                python3 -m pip uninstall px-proxy -y
            fi
        else
            if [ "$TEST" = "yes" ]; then
                if [ ! -d "$WHEELS" ]; then
                    echo "Wheels missing => ./build.sh -b -d"
                    $SHELL
                    exit
                fi

                # Install wheel dependencies
                python3 -m pip install px-proxy --no-index -f $WHEELS

                # Run tests
                python3 test.py $SUBCOMMAND
            else
                if [ -d "$WHEELS" ]; then
                    # Install Px dependencies if available
                    python3 -m pip install px-proxy --no-index -f $WHEELS
                fi

                # Start shell
                $SHELL
            fi
        fi
    fi

elif [ "$OS" = "Darwin" ]; then
    # OSX build

    ARCH=`uname -m`

    export PXBIN="`pwd`/px.dist-osx-$ARCH/px.dist/px"
    export WHEELS="`pwd`/px.dist-wheels-osx-$ARCH/px.dist-wheels"

    export PROXY="127.0.0.1:3127"
    export OSX_USERNAME="test"
    export PX_PASSWORD="12345"
    export PX_CLIENT_USERNAME=$OSX_USERNAME
    export PX_CLIENT_PASSWORD=$PX_PASSWORD

    # Install brew
    if ! brew -v > /dev/null; then
        bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi

    # Install all versions of Python in brew
    for pyver in `brew search "/^python@3.*$/" | sort -n -t . -k 2 | cut -d "@" -f 2,2`
    do
        export PY="/usr/local/opt/python@$pyver/bin/python$pyver"
        if [ ! -f "$PY" ]; then
            # Install Python
            brew install python@$pyver
        fi
    done

    if [ ! -f "/usr/local/bin/upx" ]; then
        # Install upx
        brew install upx
    fi

    # Pick latest-1 python if manylinux / musllinux
    #   Nuitka support lags behind Python releases
    pyvers=`ls -v /usr/local/opt | grep python@3. | sort -n -t . -k 2 | cut -d "@" -f 2,2`
    pyver=`echo "$pyvers" | tail -n 2 | head -n 1`
    export PY="/usr/local/opt/python@$pyver/bin/python$pyver"

    # Adjust Python version if specified with -v
    if [ ! -z "$PYVERSION" ]; then
        for pyver in $pyvers
        do
            if [ "$pyver" = "$PYVERSION" ]; then
                export PY="/usr/local/opt/python@$pyver/bin/python$pyver"
                break
            fi
        done
    fi

    setup_venv $PY

    if [ "$BUILD" = "yes" ]; then
        # Build both if neither specified
        if [ -z "$DEPS" ] && [ -z "$NUITKA" ]; then
            DEPS="yes"
            NUITKA="yes"
        fi

        if [ "$DEPS" = "yes" ] || [ ! -d "$WHEELS" ]; then
            # Also run if $WHEELS does not exist since NUITKA depends on wheels
            rm -rf $WHEELS

            for pyver in $pyvers
            do
                # Run only for Python version if specified with -v
                if [ ! -z "$PYVERSION" ] && [ "$pyver" != "$PYVERSION" ]; then
                    continue
                fi

                # Setup venv for this Python version
                setup_venv "/usr/local/opt/python@$pyver/bin/python$pyver"

                # Install tools
                python3 -m pip install --upgrade pip setuptools build wheel

                # Build dependency wheels
                python3 tools.py --deps
            done

            # If no wheels generated, exit
            if [ ! -d "$WHEELS" ]; then
                echo "No wheels generated - $PYVERSION not found?"
                exit
            fi

            # Activate latest-1 Python version
            activate_venv $PY

            # Create any wheel if not already
            python3 tools.py --wheel

            # Package all wheels
            python3 tools.py --depspkg
        fi

        if [ "$NUITKA" = "yes" ]; then
            # Install tools
            python3 -m pip install --upgrade pip setuptools build wheel nuitka

            # Install wheel dependencies
            python3 -m pip install px-proxy --no-index -f $WHEELS

            # Build Nuitka binary
            python3 tools.py --nuitka

            # Uninstall Px
            python3 -m pip uninstall px-proxy -y
        fi
    else
        python3 -m pip install --upgrade pip

        if [ "$TEST" = "yes" ]; then
            if [ ! -d "$WHEELS" ]; then
                echo "Wheels missing => ./build.sh -b -d"
                exit
            fi

            # Install wheel dependencies
            python3 -m pip install px-proxy --no-index -f $WHEELS

            # Run tests
            python3 test.py $SUBCOMMAND
        else
            if [ -d "$WHEELS" ]; then
                # Install Px dependencies if available
                python3 -m pip install px-proxy --no-index -f $WHEELS
            fi
        fi
    fi

else
    # Build / start containers on Linux

    # Detect architecture
    if [ -z "$ARCH" ]; then
        ARCH=`uname -m`
    elif [ "$ARCH" != `uname -m` ]; then
        # Install binfmt to add support for multiple architectures
        docker run --privileged --rm tonistiigi/binfmt --install all
    fi

    # Docker flags
    DOCKERCMD="docker run -it --network host --privileged -v `pwd`:/px -v /root/.ssh:/root/.ssh"

    # Forward env vars to container
    if [ ! -z "$REMOTE_SSH" ]; then
        DOCKERCMD="$DOCKERCMD -e REMOTE_SSH"
    fi

    if [ "$BUILD" = "yes" ]; then
        # Which image to load
        if [ -z "$IMAGE" ] || [ "$IMAGE" = "all" ]; then
            IMAGE="musl glibc"
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
            gen_px_image $image
            $DOCKERCMD --rm $PX_IMAGE /px/build.sh -b $SUBCOMMAND
        done
    elif [ "$TEST" = "yes" ]; then
        # Check if test env vars are set
        if [ -z "$REMOTE_SSH" ]; then
            echo "REMOTE_SSH not configured"
        fi

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
            gen_px_image $image
            $DOCKERCMD --rm $PX_IMAGE /px/build.sh -t "$SUBCOMMAND"
        done
    else
        if [ -z "$IMAGE" ]; then
            echo "$USAGE"
            exit 1
        fi

        gen_px_image $IMAGE

        if [ -z "$SUBCOMMAND" ]; then
            $DOCKERCMD --rm $PX_IMAGE /px/build.sh
        else
            $DOCKERCMD --rm $PX_IMAGE $SUBCOMMAND
        fi
    fi

fi