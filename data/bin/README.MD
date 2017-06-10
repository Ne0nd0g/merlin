# Merlin Binaries

This directory contains compiled binaries for different operating
 systems and architectures. A list of golang supported operating
 systems and architectures can be found here:
 https://golang.org/doc/install/source#environment

This directory is here because the `bin` in the root of the Merlin's
 folders is used and created by golang for subsequent binaries.

The agent & server can be cross-compiled using:
 `GOOS=darwin GOARCH=amd64 go build -o bin\merlinserver.dmg merlinserver.go`


The gomobile library can be used to compile for Android and iOS:
 https://godoc.org/golang.org/x/mobile/cmd/gomobile


$GOOS   |   $GOARCH
---     |   ---
android |   arm
darwin  |   386
darwin  |   amd64
darwin  |   arm
darwin  |   arm64
dragonfly   |   amd64
freebsd |   386
freebsd |   amd64
freebsd |   arm
linux   |   386
linux   |   amd64
linux   |   arm
linux   |   arm64
linux   |   ppc64
linux   |   ppc64le
linux   |   mips
linux   |   mipsle
linux   |   mips64
linux   |   mips64le
netbsd  |   386
netbsd  |   amd64
netbsd  |   arm
openbsd |   386
openbsd |   amd64
openbsd |   arm
plan9   |   386
plan9   |   amd64
solaris |   amd64
windows |   386
windows |   amd64

# Compile for Android
These instructions can be followed to compile for Android

  * Install Android SDK
 https://developer.android.com/ndk/guides/index.html
  * Install gomobile
  `go get golang.org/x/mobile/cmd/gomobile`
  * Initialize gomobile
  `bin\gomobile init
  -ndk=C:\Users\[username]\AppData\Local\Android\Sdk\ndk-bundle`
  * Build the APK `bin\gomobile build -target=android merlinagent`