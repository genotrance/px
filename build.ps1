# Install scoop
if ($null -eq (Get-Command "scoop" -ErrorAction SilentlyContinue)) {
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
    Invoke-RestMethod get.scoop.sh | Invoke-Expression

    # Install versions bucket
    scoop bucket add versions -ErrorAction SilentlyContinue
}

# Python versions to support: 3.7 - 3.11
$BASE = 3
$OLDEST = 7
$LATEST = 11

# Generate version list
$PYVERSIONS = @()
for ($i = $OLDEST; $i -le $LATEST; $i++) {
    $PYVERSIONS += "$BASE" + $i
}
$PY = "python$BASE$LATEST"

# Delete depspkg directory
Remove-Item -Recurse -Force px.dist-wheels-windows-amd64 -ErrorAction SilentlyContinue

# Setup Python and dependencies, build wheels for Px
foreach ($pyver in $PYVERSIONS) {
    if ($null -eq (Get-Command "python$pyver" -ErrorAction SilentlyContinue)) {
        # Install Python
        scoop install python$pyver
    }

    # Tools
    Invoke-Expression "python$pyver -m pip install --upgrade pip setuptools build wheel"

    # Create wheel dependencies for this Python version
    Invoke-Expression "python$pyver tools.py --deps"
}

# Install build tools
Invoke-Expression "$PY -m pip install --upgrade twine"

# Install wheel dependencies
Invoke-Expression "$PY -m pip install --upgrade px-proxy --no-index -f px.dist-wheels-windows-amd64\px.dist-wheels"

# Download libcurl
Invoke-Expression "$PY tools.py --libcurl"

# Build wheels
Invoke-Expression "$PY tools.py --wheel"

# Create package of all dependencies
Invoke-Expression "$PY tools.py --depspkg"

# Build embedded binary
Invoke-Expression "$PY tools.py --embed --tag=$BASE.$LATEST"

# Uninstall Px
Invoke-Expression "$PY -m pip uninstall px-proxy -y"