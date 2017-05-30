# pflogd
PF logger for macOS - logging deamon for macOS to capture traffic managed by PF (packet filter).

### Build
1. `mkdir .build`
2. `cd .build`
3. `cmake .. && make`

Once built pflogd executable will appear in .build folder.

### Installation
1. Modify `pflogd.sh` if needed
2. Copy `pflogd.sh` to `/usr/local/sbin`
3. `sudo chmod 755 /usr/local/sbin/pflogd.sh`
4. `sudo chown root:wheel /usr/local/sbin/pflogd.sh`
5. Copy `com.apple.pflogd.plist` to `/Library/LaunchDaemons`
6. `sudo chmod 644 /Library/LaunchDaemons/com.apple.pflogd.plist`
7. `sudo chown root:wheel /Library/LaunchDaemons/com.apple.pflogd.plist`
8. Copy `pflogd` to `/usr/local/sbin/`
9. `sudo chmod 755 /usr/local/sbin/pflogd`
10. `sudo chown root:wheel /usr/local/sbin/pflogd`
11. Add following line: `/var/log/pflogd.log 644  10   6000 *    J` to `/etc/newsyslog.conf`. It would enable logs rotation.
12. Restart the system

--
### Apple notes on daemon development
When you install your daemon, make sure that you set the file system permissions correctly. Apple recommends that daemons be owned by root, have an owning group of wheel, and use permissions 755 (rwxr-xr-x) for executables and directories, and 644 (rw-r--r--) for files. In addition, every directory from your daemon up to the root directory must be owned by root and only writable by the owner (or owned by root and sticky). If you don't do this correctly, a non-admin user might be able to escalate their privileges by modifying your daemon (or shuffling it aside).

### Links
- [PF: The OpenBSD Packet Filter](http://gd.tuwien.ac.at/.vhost/www.openbsd.org/xxx/faq/pf/index.html)
- [Firewalling with OpenBSD's PF packet filter](https://home.nuug.no/~peter/pf/en/long-firewall.html)
