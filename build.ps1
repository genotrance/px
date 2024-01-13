# Builds wheels for all versions of Python since -OLDEST minor version
#
# To build for a single version of Python, set -MINOR = X
# E.g. for 3.10 => .\build.ps1 -MINOR 10

# Python versions to support
param (
    [Parameter(Mandatory = $false)][int]$MAJOR = 3,
    [Parameter(Mandatory = $false)][int]$MINOR = -1,

    # Oldest Python versions supported
    [Parameter(Mandatory = $false)][int]$OLDEST = 7
)

# Install scoop
if ($null -eq (Get-Command "scoop" -ErrorAction SilentlyContinue)) {
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
    Invoke-RestMethod get.scoop.sh | Invoke-Expression

    # Install versions bucket
    scoop bucket add versions -ErrorAction SilentlyContinue
}

# Delete depspkg directory
Remove-Item -Recurse -Force px.dist-wheels-windows-amd64 -ErrorAction SilentlyContinue

# Install latest Python
if ($null -eq (Invoke-Expression "scoop list ^python$")) {
    # Install Python
    scoop install python
} else {
    # Upgrade Python
    scoop update python
    
    # Make latest Python the default
    scoop reset python
}

# Get latest minor version
$LATEST = (Invoke-Expression "python -c 'import sys; print(sys.version_info[1])'")

# Check MINOR is valid
if ($MINOR -ne -1 -and (($MINOR -gt $LATEST) -or ($MINOR -lt $OLDEST))) {
    Write-Host "Invalid minor version specified: $MINOR"
    Write-Host "Valid versions: $OLDEST - $LATEST"
    exit 1
}

# Setup Python and dependencies, build wheels for Px
$pyver = ""
$count = $OLDEST
while ($count -le $LATEST) {
    if ($MINOR -ne -1) {
        # Minor specified - skip other versions
        if ($count -lt $MINOR) {
            # Keep counting
            $count += 1
            continue
        } elseif ($count -gt $MINOR) {
            # Too high, we are done
            break
        }
    }

    # Install / upgrade if not latest (done earlier)
    if ($count -ne $LATEST) {
        $pyver = "$MAJOR$count"
        if ($null -eq (Get-Command "python$pyver" -ErrorAction SilentlyContinue)) {
            # Install Python
            scoop install python$pyver
        } else {
            # Upgrade Python
            scoop update python$pyver
        }
    } else {
        $pyver = ""
    }

    # Tools
    Invoke-Expression "python$pyver -m pip install --upgrade pip setuptools build wheel"

    # Create wheel dependencies for this Python version
    Invoke-Expression "python$pyver tools.py --deps"

    if ($pyver -eq "" -or $MINOR -ne -1) {
        # Done processing latest Python or specified minor
        break
    }
    $count += 1
}

# Make latest Python the default
Invoke-Expression "scoop reset python"

# Install build tools
Invoke-Expression "python$pyver -m pip install --upgrade twine"

# Install wheel dependencies
Invoke-Expression "python$pyver -m pip install --upgrade px-proxy --no-index -f px.dist-wheels-windows-amd64\px.dist-wheels"

# Download libcurl
Invoke-Expression "python$pyver tools.py --libcurl"

# Build wheels
Invoke-Expression "python$pyver tools.py --wheel"

# Create package of all dependencies
Invoke-Expression "python$pyver tools.py --depspkg"

# Build embedded binary
Invoke-Expression "python$pyver tools.py --embed --tag=$MAJOR.$count"

# Uninstall Px
Invoke-Expression "python$pyver -m pip uninstall px-proxy -y"