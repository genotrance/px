#! /bin/sh

set -e

USAGE="
./build.sh [-i IMAGE] ([-b] [-d] [-n] [-a ARCH]) ([-t] [-s SUBCOMMAND])

-b = build
  -i IMAGE = glibc | musl | any Docker tag - default = glibc + musl
  -d = deps
  -n = nuitka
  -a ARCH = aarch64 | i686 ... - default = host architecture
-t = test
  -i IMAGE = alpines | ubuntus | debians | mints | opensuses | any Docker tag
  -s SUBCOMMAND = forwarded

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

OS=`uname -s | tr '[:upper:]' '[:lower:]' | cut -d '/' -f 2 | cut -d '_' -f 1`
TMP=${TMP:-/tmp}
UV="uv --no-config"

PYVERS=`grep envlist pyproject.toml | grep -oE '[0-9]+' | tr '\n' ' '`
PYMAIN=`echo $PYVERS | awk '{print $(NF-1)}'`

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
VPATH="import sys; print(f'py{sys.version_info.major}{sys.version_info.minor}')"
TESTDEPS=`grep commands_pre pyproject.toml | grep -oE '[A-Za-z\-]+' | tr '\n' ' ' | sed -n 's/.*install //p'`

setup_venv() {
    VENV=$TMP/`$1 -c "$VPATH"`
    if [ ! -d "$VENV" ]; then
        echo "Setup $VENV"
        $UV venv -p $1 --no-project $VENV
        FRESH=True
    fi
    if [ "$OS" = "windows" ]; then
        . $VENV/Scripts/activate
    else
        . $VENV/bin/activate
    fi
    if [ "$FRESH" = "True" ]; then
        $UV pip install --upgrade pip pymcurl setuptools build wheel cffi $TESTDEPS -f mcurllib
    fi
}

activate_venv() {
    VENV=$TMP/`$1 -c "$VPATH"`
    echo "Activate $VENV"
    if [ "$OS" = "windows" ]; then
        . $VENV/Scripts/activate
    else
        . $VENV/bin/activate
    fi
}

gen_px_image() {
    # Python wheel containers for musl and glibc
    MUSL="quay.io/pypa/musllinux_1_2_$ARCH"
    GLIBC="quay.io/pypa/manylinux2014_$ARCH"

    # Split $1 into tag and version
    TAG=`echo $1 | cut -d ":" -f 1`
    if [ "$TAG" = "$1" ]; then
        VERSION="latest"
    else
        VERSION=`echo $1 | cut -d ":" -f 2`
    fi

    # Create image tag
    PX_IMAGE="px_$TAG"_"$ARCH:$VERSION"

    # Generate if image does not exist
    exists=`docker images -q $PX_IMAGE`
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
        sleep 1
        CONTAINER_ID=`docker ps -lq -f "status=exited"`
        if [ -z "$CONTAINER_ID" ]; then
            echo "No container ID found"
            exit
        fi
        docker commit $CONTAINER_ID $PX_IMAGE
        docker rm $CONTAINER_ID
        echo "Generated $PX_IMAGE"
    else
        echo "Tag: $PX_IMAGE"
    fi
}

add_dot() {
    # Make 312 into 3.12
    echo `echo $1 | awk '{print substr($1,1,1) "." substr($1,2)}'`
}

get_python_path() {
    if [ "$OS" = "linux" ]; then
        echo /opt/python/cp$1-cp$1/bin/python3
    elif [ "$OS" = "darwin" ]; then
        pydotver=$(add_dot $1)
        echo /usr/local/bin/python$pydotver
    elif [ "$OS" = "windows" ]; then
        $UV python install $1
        echo `$UV python find $1`
    fi
}

isolate() {
  ISOLATED=$TMP/pxbuild
  echo "Isolating to $ISOLATED"
  rm -rf $ISOLATED
  mkdir -p $ISOLATED
  cp -r -t $ISOLATED *.txt px px.* *.toml *.md tools.py
  cp -r mcurllib $ISOLATED/. || true
  cd $ISOLATED
}

deisolate() {
  ISOLATED=$TMP/pxbuild
  echo "Copying artifacts from $ISOLATED"

  cd -

  # Copy px wheel
  if [ ! -d "wheel" ]; then
    cp -r $ISOLATED/wheel .
  fi

  # Copy px.dist wheels
  whls=$ISOLATED/`dirname $1`
  rm -rf $1
  if [ -d "$whls" ]; then
    cp -r $whls .
  fi
}

if [ -f "/.dockerenv" ] || [ "$OS" = "darwin" ] || [ "$OS" = "windows" ]; then
    ARCH=`uname -m`

    # Setup dependencies
    if [ "$OS" = "linux" ]; then
        DISTRO=`cat /etc/os-release | grep ^ID | head -n 1 | cut -d"=" -f2 | sed 's/"//g'`
        SHELL="bash"
        MUSL=`ldd /bin/ls | grep musl || true`
        if [ -z "$MUSL" ]; then
            ABI="glibc"
        else
            ABI="musl"
        fi

        export PXBIN="./px.dist-linux-$ABI-$ARCH/px.dist/px"
        export WHEELS="./px.dist-linux-$ABI-$ARCH-wheels/px.dist"

        if [ "$DISTRO" = "alpine" ]; then
            if [ "$DOCKERBUILD" = "yes" ]; then
                apk update && apk upgrade
                apk add curl psmisc dbus gnome-keyring openssh \
                        ccache gcc musl-dev patchelf libffi-dev
                if [ -f "/opt/_internal/static-libs-for-embedding-only.tar.xz" ]; then
                    # Extract static libs for embedding if musllinux
                    cd /opt/_internal && tar xf static-libs-for-embedding-only.tar.xz && cd -

                    apk add upx || true
                else
                    apk add python3 python3-dev
                fi
            fi

            SHELL="sh"
        elif [ "$DISTRO" = "centos" ] || [ "$DISTRO" = "rocky" ]; then
            if [ "$DOCKERBUILD" = "yes" ]; then
                # Avoid random mirror
                cd /etc/yum.repos.d
                for file in `ls`; do sed -i~ 's/^mirrorlist/#mirrorlist/' $file; done
                for file in `ls`; do sed -i~~ 's/^#baseurl/baseurl/' $file; done
                cd -

                yum update -y
                yum install -y psmisc gnome-keyring openssh
                yum install -y libffi-devel
                yum install -y dbus-daemon || true
                yum install -y ccache || true
                yum install -y patchelf || true
                if [ -f "/opt/_internal/static-libs-for-embedding-only.tar.xz" ]; then
                    # Extract static libs for embedding if manylinux
                    cd /opt/_internal && tar xf static-libs-for-embedding-only.tar.xz && cd -

                    yum install -y upx || true
                else
                    yum install -y python3 python3-devel
                fi
                yum clean all
            fi
        elif [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ] || [ "$DISTRO" = "linuxmint" ]; then
            if [ "$DOCKERBUILD" = "yes" ]; then
                apt update -y && apt upgrade -y
                apt install -y curl psmisc python3 python3-venv \
                    dbus gnome-keyring openssh-client \
                    --no-install-recommends
                apt clean
            fi
        elif [ "$DISTRO" = "opensuse-tumbleweed" ] || [ "$DISTRO" = "opensuse-leap" ]; then
            if [ "$DOCKERBUILD" = "yes" ]; then
                zypper -n update
                zypper -n install curl psmisc python3 \
                    dbus-1-python3 gnome-keyring openssh
                zypper cc -a
            fi
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

        # Setup uv binary if needed
        if [ -z `which uv` ]; then
            if [ ! -f "$HOME/.local/bin/uv" ]; then
                curl -LsSf https://astral.sh/uv/install.sh | sh
            fi
            . ~/.local/bin/env
        fi
    elif [ "$OS" = "darwin" ]; then
        export PXBIN="./px.dist-mac-$ARCH/px.dist/px"
        export WHEELS="./px.dist-mac-$ARCH-wheels/px.dist"
    
        # Install brew
        if ! brew -v > /dev/null; then
            bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            if [ ! -f "/usr/local/bin/upx" ]; then
                # Install dependencies
                brew install curl upx uv
            fi
        fi

        # Python versions should be manually installed using python.org installers
    elif [ "$OS" = "windows" ]; then
        export PXBIN="./px.dist-windows-amd64/px.dist/px.exe"
        export WHEELS="./px.dist-windows-amd64-wheels/px.dist"

        # requires busybox and uv installed via scoop
        # uv will install Python in setup_venv if needed
    else
        echo "Unknown OS $OS"
        exit
    fi

    # Setup venvs
    if [ "$OS" = "linux" ]; then
        # Pick latest-1 python if manylinux / musllinux
        #   Nuitka support lags behind Python releases
        export PY="/opt/python/cp$PYMAIN-cp$PYMAIN/bin/python3"

        # Python not found - default - will be installed if needed
        if [ ! -f "$PY" ]; then
            export PY="python3"
            echo "Using distro Python - not manylinux / musllinux"
        fi

        if [ "$DOCKERBUILD" = "yes" ]; then
            # Run for all Python versions if manylinux/musllinux
            if [ -d "/opt/python" ]; then
                for pyver in $PYVERS
                do
                    # Setup venv for this Python version
                    setup_venv $(get_python_path $pyver)
                done
            else
                setup_venv $PY
            fi
        fi
    elif [ "$OS" = "darwin" ]; then
        for pyver in $PYVERS
        do
            pydotver=$(add_dot $pyver)
            if [ -z `which python$pydotver` ]; then
                echo "Python $pydotver not found"
                exit
            fi
            setup_venv $(get_python_path $pyver)
        done

        # Pick latest-1 python
        #   Nuitka support lags behind Python releases
        export PY="/usr/local/bin/python$(add_dot $PYMAIN)"
    elif [ "$OS" = "windows" ]; then
        for pyver in $PYVERS
        do
            setup_venv $(get_python_path $pyver)
        done

        # Pick latest-1 python
        #   Nuitka support lags behind Python releases
        export PY=`$UV python find $PYMAIN`
    fi

    activate_venv $PY
    $UV pip install --upgrade nuitka tox tox-uv twine

    if [ "$DOCKERBUILD" = "yes" ]; then
        exit
    elif [ "$OS" = "linux" ]; then
        # Start dbus and gnome-keyring
        export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --fork --config-file=/usr/share/dbus-1/session.conf --print-address`
        echo "abc" | gnome-keyring-daemon --unlock
    fi

    if [ "$BUILD" = "yes" ]; then
        # Build both if neither specified
        if [ -z "$DEPS" ] && [ -z "$NUITKA" ]; then
            DEPS="yes"
            NUITKA="yes"
        fi

        if [ "$DEPS" = "yes" ] || [ ! -d "$WHEELS" ]; then
            # Run in temp to enable parallel builds
            isolate

            # Run for all Python versions if manylinux/musllinux
            for pyver in $PYVERS
            do
                # Setup venv for this Python version
                activate_venv $(get_python_path $pyver)

                # Build dependency wheels
                python tools.py --deps
            done

            # If no wheels generated, exit
            if [ ! -d "$WHEELS" ]; then
                echo "No wheels generated"
                # Start shell
                if [ "$OS" = "linux" ]; then
                    $SHELL
                fi
                exit
            fi

            # Activate latest-1 Python version
            activate_venv $PY

            # Create any wheel if not already
            python tools.py --wheel

            # Package all wheels
            python tools.py --depspkg

            # Copy artifacts back to source dir
            deisolate $WHEELS
        fi

        if [ "$NUITKA" = "yes" ]; then
            if [ "$OS" = "windows" ]; then
                # Windows needs embedded build, not Nuitka
                python tools.py --embed
            else
                # Install wheel dependencies
                $UV pip install px-proxy --no-index -f $WHEELS

                # Build Nuitka binary
                python tools.py --nuitka

                # Uninstall Px
                $UV pip uninstall px-proxy
            fi
        fi
    fi

    if [ "$TEST" = "yes" ]; then
        export PXBIN=`pwd`/$PXBIN
        export WHEELS=`pwd`/$WHEELS

        if [ ! -d "$WHEELS" ]; then
            echo "Wheels missing => ./build.sh -b -d"
            # Start shell
            if [ "$OS" = "linux" ]; then
                $SHELL
            fi
            exit
        fi

        # Run tests
        if [ "$OS" = "windows" ]; then
            export UV_PYTHON_PREFERENCE="only-managed"
        else
            export UV_PYTHON_PREFERENCE="only-system"
        fi
        PXWHEEL=`ls -d $WHEELS/px_proxy*.whl`
        python -m tox --installpkg $PXWHEEL --override "tool.tox.env_run_base.install_command=uv pip install --no-index -f $WHEELS" --workdir $TMP || \
          (echo "Tests failed ... Ctrl-C to exit" && sleep inf)
    fi

    if [ -z "$BUILD" ] && [ -z "$TEST" ]; then
        # Install Px dependencies if available
        $UV pip install px-proxy --no-index -f $WHEELS || true

        # Start shell
        if [ "$OS" = "linux" ]; then
            $SHELL
        fi
    fi
else
    # Build / start containers on Linux

    # Docker flags
    DOCKERCMD="docker run -it --privileged -v `pwd`:/px -v /root/.ssh:/root/.ssh -w /px"

    # Detect architecture
    if [ -z "$ARCH" ]; then
        ARCH=`uname -m`
    elif [ "$ARCH" != `uname -m` ]; then
        # Install binfmt to add support for multiple architectures
        docker run --privileged --rm tonistiigi/binfmt --install all

        # Specify --platform for multi-arch images
        if [ ! "$IMAGE" = "musl" ] && [ ! "$IMAGE" = "glibc" ]; then
            DOCKERCMD="$DOCKERCMD --platform $ARCH"
        fi
    fi

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
        elif [ "$IMAGE" = "alpines" ]; then
            IMAGE="alpine alpine:3.13"
        elif [ "$IMAGE" = "ubuntus" ]; then
            IMAGE="ubuntu ubuntu:focal"
        elif [ "$IMAGE" = "debians" ]; then
            IMAGE="debian debian:oldstable"
        elif [ "$IMAGE" = "mints" ]; then
            IMAGE="linuxmintd/mint21.2-amd64 linuxmintd/mint20.3-amd64"
        elif [ "$IMAGE" = "opensuses" ]; then
            IMAGE="opensuse/tumbleweed opensuse/leap:15.1"
        elif [ "$IMAGE" = "voids" ]; then
            IMAGE="voidlinux/voidlinux voidlinux/voidlinux-musl"
        fi

        # Forward any commands
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
