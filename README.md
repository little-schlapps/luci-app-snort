# luci-app-snort

LuCI web interface for the [Snort 3](https://www.snort.org/) IDS/IPS package (`snort3`) on OpenWrt.

It adds **Services → Snort IDS** to LuCI with four pages:

| Page | What it does |
|---|---|
| **Overview** | Live status (running, version, rule count, logged alerts, memory), Start/Stop/Restart, **Update rules**, and the settings from `/etc/config/snort` (mode, capture method, interface, HOME_NET, oinkcode, include file, …). |
| **Alerts** | Summary of `/var/log/alert_json.txt`: top rules, top source addresses and the most recent alerts, with a text filter, auto-refresh and "Clear alerts". |
| **Local Rules** | Editor for your own rules (`/etc/snort/local.rules`). They are copied into the active rules directory and survive rule updates made from this UI. |
| **Log** | Snort entries from the system log (`logread`), auto-refreshing. Alerts appear here when `alert_syslog` is enabled via the include file. |

No extra daemon or port is added: the pages run inside LuCI and call a small
[rpcd ucode](root/usr/share/rpcd/ucode/luci.snort) backend (`luci.snort` ubus
object) that rpcd loads on demand. Access is limited by the ACL in
[`acl.d/luci-app-snort.json`](root/usr/share/rpcd/acl.d/luci-app-snort.json) to
these backend methods and the `snort` UCI config — the browser never runs
arbitrary commands.

## Requirements

- OpenWrt 24.10 / 25.12 or newer with LuCI
- `snort3`, `rpcd-mod-ucode` (pulled in as dependencies)
- Alert logging enabled (`option logging '1'`, the default) for the Alerts page

## Building

The package uses the standard LuCI build infrastructure (`luci.mk`) and is
architecture independent.

### In an OpenWrt SDK / buildroot

```sh
# from the SDK root
./scripts/feeds update luci && ./scripts/feeds install luci-base
cp -r /path/to/luci-app-snort feeds/luci/applications/
./scripts/feeds update -i luci && ./scripts/feeds install luci-app-snort
make defconfig
make package/luci-app-snort/compile V=s
find bin/packages -name 'luci-app-snort*'
```

Install the resulting package on the router (`apk add --allow-untrusted
./luci-app-snort-*.apk` on 25.12, or `opkg install` on 24.10).

### Quick install for development (no build)

```sh
R=root@192.168.1.1
ssh $R 'mkdir -p /www/luci-static/resources/view/snort'
scp -O htdocs/luci-static/resources/view/snort/*.js $R:/www/luci-static/resources/view/snort/
scp -O root/usr/share/luci/menu.d/luci-app-snort.json $R:/usr/share/luci/menu.d/
scp -O root/usr/share/rpcd/acl.d/luci-app-snort.json $R:/usr/share/rpcd/acl.d/
scp -O root/usr/share/rpcd/ucode/luci.snort $R:/usr/share/rpcd/ucode/
ssh $R 'rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache; service rpcd reload'
```

Then log out of LuCI and back in so the new ACL is applied to your session.

## Notes

- **Rule updates** run `/usr/bin/snort-rules` (community rules, or the
  registered ruleset when an oinkcode is set) in the background, restore your
  local rules and restart Snort. Loading rules takes 30–60 s on small routers.
- **Alerts are kept in RAM** (`/var/log`) by default and cleared on reboot.
  Change *Log directory* to persistent storage (e.g. a USB drive) to keep them;
  avoid putting a busy alert log on internal flash.
- **Use `afpacket` capture for IDS.** With the `pcap` method, packets on quiet
  interfaces can reach Snort in delayed batches, so alerts show up 60+ seconds
  late (measured on an RB5009: ~66 s with pcap, immediate with afpacket).
- **Testing with traffic generated on the router itself:** locally originated
  TCP/UDP packets are captured before checksum offload fills in the checksum,
  so Snort discards them and rules will not match. Test with traffic from
  another host (ICMP from the router works).
- **Performance:** Snort is CPU-heavy. On typical routers use it on low-volume
  segments (IoT/camera/OT networks) rather than a full gigabit WAN.
- Syslog output: add `alert_syslog = { level = 'info' }` to a Lua file such as
  `/etc/snort/local.lua` and set it as *Include file*.

## License

Apache-2.0, matching the LuCI project.
