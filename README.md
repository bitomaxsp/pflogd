# pflogd
PF logger for macOS

When you install your daemon, make sure that you set the file system permissions correctly. Apple recommends that daemons be owned by root, have an owning group of wheel, and use permissions 755 (rwxr-xr-x) for executables and directories, and 644 (rw-r--r--) for files. In addition, every directory from your daemon up to the root directory must be owned by root and only writable by the owner (or owned by root and sticky). If you don't do this correctly, a non-admin user might be able to escalate their privileges by modifying your daemon (or shuffling it aside).
