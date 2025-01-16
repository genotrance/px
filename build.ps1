# Install scoop
if ($null -eq (Get-Command "scoop" -ErrorAction SilentlyContinue)) {
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
    Invoke-RestMethod get.scoop.sh | Invoke-Expression
}

# Install git
if ($null -eq (Get-Command "git" -ErrorAction SilentlyContinue)) {
    scoop install git
    scoop update
}

# Install busybox and uv
if ($null -eq (Get-Command "busybox" -ErrorAction SilentlyContinue)) {
    scoop install busybox
}
if ($null -eq (Get-Command "uv" -ErrorAction SilentlyContinue)) {
    scoop install uv
}

busybox bash ./build.sh $Args