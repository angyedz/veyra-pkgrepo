# Veyra system updater

`veyra-update --check` lists available APK upgrades on a conventional
single-root installation. `sudo veyra-update` applies them there.

An installation marked `atomic-v1` must never upgrade the active system root
in place. In that mode, the command delegates to the root-owned
`/usr/sbin/veyra-atomic-update` helper. If the helper is absent, the command
fails without contacting APK repositories or changing packages. Unknown or
unsafe deployment-mode metadata also fails closed.

The atomic helper is not included in this package version. This package
therefore protects experimental A/B installations from accidental in-place
upgrades, but it does not provide signed system/user generation updates or
trial rollback. The path checks in this frontend are an accidental-misuse
guard, not a privilege boundary; the system environment must enforce its own
package and update policy.
