# Install scoop
if ((Get-Command "scoop" -ErrorAction SilentlyContinue) -eq $null) {
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
    irm get.scoop.sh | iex
}

# Install versions bucket
scoop bucket add versions -ErrorAction SilentlyContinue

# Python versions
$PYVERSIONS = @("37", "38", "39", "310")
$PY = "python310"

# Delete depspkg directory
Remove-Item -Recurse -Force px.dist-wheels-windows-amd64

# Setup Python and dependencies, build wheels for Px
foreach ($pyver in $PYVERSIONS) {
    if ((Get-Command "python$pyver" -ErrorAction SilentlyContinue) -eq $null) {
        # Install Python
        scoop install python$pyver
    }

    # Tools
    Invoke-Expression "python$pyver -m pip install --upgrade pip setuptools build wheel"

    # Create wheel dependencies for this Python version
    Invoke-Expression "python$pyver tools.py --deps"
}

# Install build tools
Invoke-Expression "$PY -m pip install --upgrade nuitka twine"

# Install wheel dependencies
Invoke-Expression "$PY -m pip install --upgrade px-proxy --no-index -f px.dist-wheels-windows-amd64\px.dist-wheels"

# Build wheels
Invoke-Expression "$PY tools.py --wheel"

# Create package of all dependencies
Invoke-Expression "$PY tools.py --depspkg"

# Build Nuitka
Invoke-Expression "$PY tools.py --nuitka"

# Uninstall Px
Invoke-Expression "$PY -m pip uninstall px-proxy -y"