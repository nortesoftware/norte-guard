# Where an unprivileged user namespace is actually available

Every unprivileged sandbox for `npm install` — this project's, `bwrap`, rootless podman,
`nono`, `cplt` — begins by creating a user namespace. This document establishes where that
is permitted, because the answer is not the one the usual framing assumes and it changed
recently on the most common development distribution.

**Nothing here was executed.** This machine is Debian 13, which does not ship the restriction
under study. Every behavioural claim below is quoted from kernel source, distro policy files,
a vendor advisory, or Canonical's own test plan, and the limits are stated at the end.

## The gate is two-part, and that is the whole finding

Not "can an unprivileged user create a user namespace" but:

1. **May the namespace be created?**
2. **Does the process hold capabilities inside it?**

Ubuntu 24.04+ answers **yes** to the first and **no** to the second. Any check that tests only
the first concludes, wrongly, that everything is fine.

## What Ubuntu 24.04+ actually does

`unshare(CLONE_NEWUSER)` **succeeds**. AppArmor's `apparmor_userns_create` hook does not deny
it; for an unconfined caller with the restriction on, it parses the label
`unprivileged_userns` and **transitions the new credential into that profile**
(`security/apparmor/task.c`, Ubuntu noble, `perms.allow = request` after
`ad->info = "Userns create - transitioning profile"`).

That shipped profile, `/etc/apparmor.d/unprivileged_userns`, reads:

```
profile unprivileged_userns {
     audit deny capability,
     audit deny change_profile,
     ...
     allow userns,
     # stack children to strip capabilities
     allow pix /** -> &unprivileged_userns ,
}
```

So the namespace exists and every capability inside it is gone. The failure therefore lands
one step **earlier** than "unshare is denied" — at the uid-mapping write, because
`map_write()` requires `CAP_SYS_ADMIN` in the target namespace:

```
$ unshare -U -r -m /bin/sh
unshare: write failed /proc/self/uid_map: Operation not permitted
```

— Qualys TRU advisory, captured on stock 24.04. Canonical's own SRU test plan (LP #2142792)
states the same as a control: *"`unshare -U true` runs successfully and generates an audit log
for a profile transition"* / *"`unshare -Ur true` fails with a permission denial."*

Two consequences worth stating explicitly:

- **`CAP_NET_ADMIN` is never reachable**, so a network-namespace jail cannot be configured at
  all — no `ip link`, no `ip route`, no packet filter.
- **Nesting a second user namespace does not recover it.** The profile stacks itself onto
  every child via `allow pix /** -> &unprivileged_userns`.

**This is Ubuntu-carried, not mainline.** The sysctl
`kernel.apparmor_restrict_unprivileged_userns` does not exist in mainline Linux at any
version. Mainline has had the `userns_create` hook since 6.1 and AppArmor's use of it since
6.7, but `aa_profile_ns_perm()` returns 0 immediately for an unconfined profile — so a
mainline or Debian kernel never restricts an ordinary user, whatever the kernel version.

## The remedy is a one-time privileged action, not a limitation

```
# /etc/apparmor.d/<tool>
abi <abi/4.0>,
include <tunables/global>
profile <tool> /path/to/<tool> flags=(unconfined) { userns, }
```

then `apparmor_parser -r`. This is Ubuntu's documented remedy and the same shape podman,
rootlesskit, crun, Chrome and Firefox already ship. Canonical's AppArmor maintainer states the
privileged step is deliberate: *"it deliberately requires a privileged operation, otherwise
the restriction could be trivially by-passed by exploit code."* The blunt alternative,
`sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, works but disables the mitigation
machine-wide.

So the honest claim for any userns-based tool is **"no root at run time, one root action at
install time on Ubuntu 24.04+"** — not "no root". And a tool that says "no setup required"
is wrong on the most common development distribution.

## Where it works

Gate: (a) namespace creatable, (b) capabilities inside it.

| Environment | Creatable | Caps inside | Works unprivileged | Unblock |
|---|---|---|---|---|
| Debian 11 / 12 / 13 | yes | yes | **yes** | — |
| Fedora; RHEL / Rocky / Alma 8, 9, 10 | yes | yes | **yes** | — |
| Arch (stock kernel) | yes | yes | **yes** | — |
| Arch `linux-hardened` | no | — | no | `sysctl kernel.unprivileged_userns_clone=1` |
| openSUSE Leap / Tumbleweed; NixOS; Flatcar | yes | yes | **yes** | — |
| Alpine | yes | yes | likely (`CONFIG_NET_NS` unconfirmed) | — |
| **Ubuntu 22.04 LTS** (incl. HWE 6.8) | yes | yes | **yes** | — |
| **Ubuntu 23.10** | yes | yes | **yes** (shipped the knob at `0`) | — |
| **Ubuntu 24.04 LTS / 24.10** | yes | **no** | **no** | profile, or machine-wide sysctl |
| **Ubuntu 25.04 / 25.10 / 26.04** | yes | **no** | **no** | same; `aa-exec` into a permissive profile no longer works |
| Any Ubuntu with LXD installed and running | yes | yes | **yes** | (already off — LXD disables the feature) |
| **WSL2, incl. an Ubuntu 24.04 rootfs** | yes | yes | **yes** — opposite of the same rootfs on metal | — |
| Android | not built | — | no | none |
| **GitHub Actions `ubuntu-latest` / `ubuntu-24.04`** | yes | **no** | **no** | `sudo sysctl -w …=0` (runners have passwordless sudo) |
| GitHub Actions `ubuntu-22.04` | yes | yes | **yes** | — |
| GitLab SaaS runners (privileged); CircleCI docker | yes | yes | **yes** | — |
| **Inside `docker run`, default seccomp, ANY host** | **no** | — | **no** | `--security-opt seccomp=unconfined`, `--cap-add SYS_ADMIN`, or `--privileged` |
| Inside `podman run`, default | yes | yes | **yes** | — |
| Kubernetes pod, default | yes | yes | host kernel governs | `seccompProfile: RuntimeDefault` re-blocks |
| Amazon Linux 2023 · Google COS · ChromeOS · Gentoo | ? | ? | **unverified — do not claim** | — |

Two rows deserve emphasis because they are easy to get backwards. **The container image is
never the deciding factor** — a `node:22` image on a Debian host works and the same image on
an Ubuntu 24.04 host does not; the host kernel and its policy decide. And **Docker's default
seccomp profile blocks `unshare` outright on any host**, gating it behind `CAP_SYS_ADMIN`
(`moby/profiles/seccomp/default.json`), so "it just runs inside the user's existing
containerised CI" is false by default regardless of distribution. Podman allows it
unconditionally; GitLab and CircleCI work for unrelated reasons (privileged mode, a patched
seccomp profile) rather than by design.

The direction of travel is toward more restriction, not less: Ubuntu has tightened every
release since 23.10, GitHub declined to disable it in the runner image
(`actions/runner-images` #10443, PR #11489 closed "workaround already provided"), and the
justification is a real CVE history. Plan for this permanently rather than waiting it out.

## Limits

- **No Ubuntu kernel was booted.** Documentation and source only, by design.
- Three inferences would change the conclusion if wrong, in priority order:
  1. That a profile attached to a tool's own binary covers a **child** `/usr/bin/unshare`. No
     cited source states this for `unshare`; it is inferred from an equivalent case where the
     child was `/usr/bin/bwrap` and the reporter confirmed the fix. If AppArmor instead
     re-evaluates at the child's `create_user_ns()`, the profile remedy collapses and only the
     machine-wide sysctl remains.
  2. That a profile attached to a path under `$HOME` loads and takes effect. If not,
     deployment requires installing to a root-owned path, which is a heavier instruction.
  3. That the entry point is a **binary**. If it is a script, the profile must attach to the
     interpreter — and granting `/usr/bin/node flags=(unconfined) { userns, }` hands userns
     plus full in-namespace capabilities to every node process on the machine, which is a real
     weakening of the host's mitigation and probably unacceptable.
- The escape-hatch enumeration is incomplete: the lane covering `aa-exec`, shipped profiles
  and the unconfined knobs did not complete.

**The cheapest experiment that would settle it** is one GitHub Actions workflow pinned to
`runs-on: ubuntu-24.04` — free, ~90 seconds, and it exercises a real Ubuntu 24.04 kernel with
the restriction live. Run `unshare -U true`, then `unshare -Ur true`, then the full
construction, and read the audit log. That settles the mechanism and the CI table row at once.
