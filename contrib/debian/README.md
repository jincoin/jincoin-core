
Debian
====================
This directory contains files used to package jincoind/jincoin-qt
for Debian-based Linux systems. If you compile jincoind/jincoin-qt yourself, there are some useful files here.

## jincoin: URI support ##


jincoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install jincoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your jincoin-qt binary to `/usr/bin`
and the `../../share/pixmaps/bitcoin128.png` to `/usr/share/pixmaps`

jincoin-qt.protocol (KDE)

